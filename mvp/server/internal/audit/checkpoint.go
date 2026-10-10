package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Checkpoints (design §13.6): every Every (default 5 min) or EveryEvents
// (default 1000) new events, each tenant's chain head is signed with the
// platform audit key and anchored outside the database, so even a database
// owner who rewrites the chain cannot rewrite what was anchored.

// CheckpointType is the JWS "typ" header of a checkpoint.
const CheckpointType = "tessera-audit-checkpoint+jwt"

// ActionCheckpointCreated is the event each checkpoint covers (its own head).
const ActionCheckpointCreated = "audit.checkpoint.created"

// CheckpointPayload is the signed content of a checkpoint.
type CheckpointPayload struct {
	Iss      string `json:"iss"`
	TID      string `json:"tid"`
	Slug     string `json:"slug"`
	Seq      int64  `json:"seq"`
	HeadHash string `json:"head_hash"`
	IAT      int64  `json:"iat"`
}

// SignCheckpoint returns the compact JWS of p signed with the platform key.
func SignCheckpoint(key *keys.SigningKey, p CheckpointPayload) (string, error) {
	if key == nil || key.Alg != keys.AlgEdDSA {
		return "", errors.New("audit: checkpoints are signed with the EdDSA platform key")
	}
	priv, ok := key.Key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("audit: platform key is not Ed25519")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: priv, KeyID: key.KID}},
		(&jose.SignerOptions{}).WithType(CheckpointType))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// ErrCheckpointSignature is wrapped by every checkpoint verification failure.
var ErrCheckpointSignature = errors.New("audit: checkpoint signature invalid")

// maxJWSBytes caps a checkpoint JWS before parsing.
const maxJWSBytes = 4096

// VerifyCheckpointJWS checks a checkpoint's signature with the platform key
// named by its kid (EdDSA only) and returns its payload.
func VerifyCheckpointJWS(s string, pub map[string]ed25519.PublicKey) (CheckpointPayload, string, error) {
	var p CheckpointPayload
	if len(s) > maxJWSBytes {
		return p, "", fmt.Errorf("%w: too large", ErrCheckpointSignature)
	}
	obj, err := jose.ParseSigned(s, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return p, "", fmt.Errorf("%w: %v", ErrCheckpointSignature, err)
	}
	if len(obj.Signatures) != 1 {
		return p, "", fmt.Errorf("%w: want one signature", ErrCheckpointSignature)
	}
	h := obj.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != CheckpointType {
		return p, h.KeyID, fmt.Errorf("%w: typ %q", ErrCheckpointSignature, typ)
	}
	key, ok := pub[h.KeyID]
	if !ok {
		return p, h.KeyID, fmt.Errorf("%w: unknown or revoked kid %q", ErrCheckpointSignature, h.KeyID)
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return p, h.KeyID, fmt.Errorf("%w: %v", ErrCheckpointSignature, err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, h.KeyID, fmt.Errorf("%w: payload: %v", ErrCheckpointSignature, err)
	}
	return p, h.KeyID, nil
}

// PlatformPublicKeys returns the platform audit keys that can verify
// checkpoints, by kid: active and retired ones, never revoked ones.
func PlatformPublicKeys(ctx context.Context, db *store.DB) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	err := db.InSystem(ctx, "audit: platform public keys", func(sys *store.SystemTx) error {
		set, err := keys.PlatformJWKS(sys)
		if err != nil {
			return err
		}
		for _, k := range set.Keys {
			if pk, ok := k.Key.(ed25519.PublicKey); ok {
				out[k.KeyID] = pk
			}
		}
		return nil
	})
	return out, err
}

// ---------------------------------------------------------------- anchor sinks

// Anchor is what a sink stores for one checkpoint.
type Anchor struct {
	TID      string `json:"tid"`
	Slug     string `json:"slug"`
	Seq      int64  `json:"seq"`
	HeadHash string `json:"head_hash"`
	JWS      string `json:"jws"`
	At       string `json:"anchored_at"`
}

// Sink stores anchors outside the database.
type Sink interface {
	// Anchor stores a and returns a reference to it (file:<line>, or an
	// object key and version).
	Anchor(ctx context.Context, a Anchor) (string, error)
}

// ErrS3NotImplemented is returned by the S3 Object Lock sink until PR14.
var ErrS3NotImplemented = errors.New("audit: the s3:// anchor sink (S3 Object Lock) is not implemented yet (PR14)")

// NewSink returns the sink for a TESSERA_AUDIT_ANCHOR URL: file:///path (or
// file://relative/path) appends to a JSONL file; s3://bucket/prefix is the
// production sink (a stub that always fails until PR14, so checkpoints stay
// "failed" and verification reports them). An empty URL means no anchoring.
func NewSink(anchorURL string) (Sink, error) {
	switch {
	case anchorURL == "":
		return nil, nil
	case strings.HasPrefix(anchorURL, "file://"):
		p, err := FilePath(anchorURL)
		if err != nil {
			return nil, err
		}
		return &FileSink{Path: p}, nil
	case strings.HasPrefix(anchorURL, "s3://"):
		return S3Sink{URL: anchorURL}, nil
	}
	return nil, fmt.Errorf("audit: unsupported anchor URL %q (want file:// or s3://)", anchorURL)
}

// FilePath returns the path of a file:// anchor URL.
func FilePath(anchorURL string) (string, error) {
	p, ok := strings.CutPrefix(anchorURL, "file://")
	if !ok || p == "" {
		return "", fmt.Errorf("audit: not a file:// anchor URL: %q", anchorURL)
	}
	return filepath.Clean(p), nil
}

// FileSink appends one JSON line per checkpoint to a file opened with
// O_APPEND and fsyncs it (dev default). anchor_ref is "file:<line-no>".
type FileSink struct {
	Path string
	mu   sync.Mutex
}

// Anchor appends a and returns its 1-based line number.
func (f *FileSink) Anchor(_ context.Context, a Anchor) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o750); err != nil {
		return "", err
	}
	lines, err := countLines(f.Path)
	if err != nil {
		return "", err
	}
	line, err := ojson.Marshal(a)
	if err != nil {
		return "", err
	}
	fh, err := os.OpenFile(f.Path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- operator-configured anchor path
	if err != nil {
		return "", err
	}
	if _, err := fh.Write(append(line, '\n')); err != nil {
		_ = fh.Close()
		return "", err
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return "", err
	}
	if err := fh.Close(); err != nil {
		return "", err
	}
	return "file:" + strconv.Itoa(lines+1), nil
}

func countLines(path string) (int, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator-configured anchor path
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	n := 0
	buf := make([]byte, 32<<10)
	for {
		c, err := fh.Read(buf)
		n += bytes.Count(buf[:c], []byte{'\n'})
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
	}
}

// S3Sink is the production anchor sink (S3 Object Lock, compliance mode, 7
// years), not implemented until PR14.
type S3Sink struct{ URL string }

// Anchor always fails with ErrS3NotImplemented.
func (S3Sink) Anchor(context.Context, Anchor) (string, error) { return "", ErrS3NotImplemented }

// AnchorSet is the content of an anchor source, for verification.
type AnchorSet struct {
	byKey map[string][]string // tid|seq -> JWSs (a reseeded dev database can reuse a seq)
	Lines int
}

func anchorKey(tid string, seq int64) string { return tid + "|" + strconv.FormatInt(seq, 10) }

// Has reports whether the exact checkpoint JWS was anchored for tid and seq.
func (s *AnchorSet) Has(tid string, seq int64, jws string) bool {
	for _, j := range s.byKey[anchorKey(tid, seq)] {
		if j == jws {
			return true
		}
	}
	return false
}

// maxAnchorLine caps one line of an anchor file.
const maxAnchorLine = 16 << 10

// ReadAnchors reads a JSONL anchor file. Malformed lines are an error: an
// anchor source that cannot be read cannot vouch for anything.
func ReadAnchors(path string) (*AnchorSet, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator-supplied anchor path
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return ParseAnchors(fh)
}

// ParseAnchors parses JSONL anchors.
func ParseAnchors(r io.Reader) (*AnchorSet, error) {
	s := &AnchorSet{byKey: map[string][]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxAnchorLine)
	for sc.Scan() {
		s.Lines++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var a Anchor
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			return nil, fmt.Errorf("audit: anchors line %d: %w", s.Lines, err)
		}
		k := anchorKey(a.TID, a.Seq)
		s.byKey[k] = append(s.byKey[k], a.JWS)
	}
	return s, sc.Err()
}

// ---------------------------------------------------------------- checkpointer

// Checkpointer creates and anchors checkpoints.
type Checkpointer struct {
	DB     *store.DB
	Sealer *seal.Sealer
	Sink   Sink // nil: checkpoints are created but not anchored
	Clock  timeutil.Clock
	Issuer string // iss of the payload (TESSERA_PUBLIC_URL)
	// A tenant is checkpointed when it has new events and either EveryEvents
	// of them or Every has passed since its last checkpoint (or it has none).
	Every       time.Duration
	EveryEvents int64
	Log         *slog.Logger
	// Only, when set, limits a run to the tenants it accepts (the CLI's -tenant).
	Only func(store.Tenant) bool
}

// maxAnchorAttempts is when a failing anchor is reported as an alert.
const maxAnchorAttempts = 3

// RunResult says what one run did.
type RunResult struct {
	Created  int
	Anchored int
	Failed   int
}

// Run checkpoints every tenant that is due (all with new events when force
// is set), including _platform, then anchors every pending or failed
// checkpoint. A failure in one tenant does not stop the others.
func (c *Checkpointer) Run(ctx context.Context, force bool) (RunResult, error) {
	var res RunResult
	clock := c.Clock
	if clock == nil {
		clock = timeutil.System
	}
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	if _, ok := store.AuditContextFrom(ctx); !ok {
		ctx = WithSystemActor(ctx, "audit.checkpointer")
	}
	var tenants []store.Tenant
	if err := c.DB.InSystem(ctx, "audit checkpoints: list tenants", func(s *store.SystemTx) error {
		var err error
		tenants, err = s.Tenants()
		return err
	}); err != nil {
		return res, err
	}
	var key *keys.SigningKey
	loadKey := func() error {
		if key != nil {
			return nil
		}
		return c.DB.InSystem(ctx, "audit checkpoints: platform key", func(s *store.SystemTx) error {
			var err error
			key, err = keys.ActivePlatformKey(s, c.Sealer)
			return err
		})
	}
	var errs []error
	for _, t := range tenants {
		if t.Status != "active" || (c.Only != nil && !c.Only(t)) {
			continue
		}
		due, err := c.due(ctx, t.ID, clock(), force)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
			continue
		}
		if due {
			if err := loadKey(); err != nil {
				return res, fmt.Errorf("audit: checkpoint key: %w", err)
			}
			if err := c.create(ctx, t, key, clock()); err != nil {
				errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
				continue
			}
			res.Created++
		}
		a, f, err := c.anchorPending(ctx, t, clock(), log)
		res.Anchored += a
		res.Failed += f
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return res, errors.Join(errs...)
}

func (c *Checkpointer) due(ctx context.Context, t tenancy.ID, now time.Time, force bool) (bool, error) {
	var due bool
	err := c.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		head, err := tx.AuditHead()
		if err != nil {
			return err
		}
		last, err := tx.LatestAuditCheckpoint()
		if errors.Is(err, store.ErrNotFound) {
			due = head.LastSeq > 0
			return nil
		}
		if err != nil {
			return err
		}
		if head.LastSeq <= last.Seq {
			return nil // nothing new
		}
		due = force || (c.EveryEvents > 0 && head.LastSeq-last.Seq >= c.EveryEvents) ||
			(c.Every > 0 && now.Sub(last.CreatedAt) >= c.Every)
		return nil
	})
	return due, err
}

// create appends the audit.checkpoint.created event and signs the head it
// produces (so the checkpoint covers its own event and an idle chain stays
// idle), in one transaction.
func (c *Checkpointer) create(ctx context.Context, t store.Tenant, key *keys.SigningKey, now time.Time) error {
	return c.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		head, err := tx.AuditHead()
		if err != nil {
			return err
		}
		ev, err := Record(ctx, tx, ActionCheckpointCreated, ojson.Object{{Key: "seq", Value: head.LastSeq + 1},
			{Key: "kid", Value: key.KID}}, At(now))
		if err != nil {
			return err
		}
		jws, err := SignCheckpoint(key, CheckpointPayload{Iss: c.Issuer, TID: t.ID.String(), Slug: t.Slug,
			Seq: ev.Seq, HeadHash: ev.Hash, IAT: now.Unix()})
		if err != nil {
			return err
		}
		_, err = tx.InsertAuditCheckpoint(store.AuditCheckpoint{Seq: ev.Seq, HeadHash: ev.Hash, JWS: jws, CreatedAt: now})
		return err
	})
}

// anchorPending stores every pending or failed checkpoint of t in the sink.
func (c *Checkpointer) anchorPending(ctx context.Context, t store.Tenant, now time.Time, log *slog.Logger) (anchored, failed int, err error) {
	if c.Sink == nil {
		return 0, 0, nil
	}
	var pending []*store.AuditCheckpoint
	if err := c.DB.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
		var err error
		pending, err = tx.UnanchoredAuditCheckpoints()
		return err
	}); err != nil {
		return 0, 0, err
	}
	for _, ck := range pending {
		ref, aerr := c.Sink.Anchor(ctx, Anchor{TID: t.ID.String(), Slug: t.Slug, Seq: ck.Seq, HeadHash: ck.HeadHash,
			JWS: ck.JWS, At: now.UTC().Format(TimeLayout)})
		status, refp := store.AnchorAnchored, &ref
		if aerr != nil {
			status, refp = store.AnchorFailed, nil
			failed++
			lvl := slog.LevelWarn
			if ck.AnchorAttempts+1 >= maxAnchorAttempts {
				lvl = slog.LevelError // alert: anchoring keeps failing
			}
			log.Log(ctx, lvl, "audit checkpoint anchoring failed", "tenant", t.Slug, "seq", ck.Seq,
				"attempts", ck.AnchorAttempts+1, "err", aerr, "critical", lvl == slog.LevelError)
		} else {
			anchored++
		}
		if err := c.DB.InTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			return tx.SetAuditCheckpointAnchor(ck.ID, status, refp, now)
		}); err != nil {
			return anchored, failed, err
		}
	}
	return anchored, failed, nil
}

// Loop runs Run every interval until ctx ends.
func (c *Checkpointer) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	for {
		if _, err := c.Run(ctx, false); err != nil && ctx.Err() == nil {
			log.Error("audit checkpoint run failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
