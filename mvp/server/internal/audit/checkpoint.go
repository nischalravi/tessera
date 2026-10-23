package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/go-jose/go-jose/v4"
	"github.com/nischalravi/tessera/mvp/server/internal/objstore"

	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
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
// checkpoints, by kid: active and retired ones, never revoked ones. A bad
// stored key is left out and alerted on slog.Default() (keys.PlatformJWKS).
func PlatformPublicKeys(ctx context.Context, db *store.DB) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	err := db.InSystem(ctx, "audit: platform public keys", func(sys *store.SystemTx) error {
		set, err := keys.PlatformJWKS(sys, nil)
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

// SinkOption configures NewSink.
type SinkOption func(*sinkOptions)

type sinkOptions struct {
	httpClient *http.Client
	s3         S3API
	obj        *objstore.Deps
}

// WithObjectStores supplies the credentials sources of the azure:// and gs://
// anchor sinks (their client is the safehttp client in deps.HTTP).
func WithObjectStores(d objstore.Deps) SinkOption { return func(o *sinkOptions) { o.obj = &d } }

// WithHTTPClient sets the HTTP client the s3:// sink's AWS SDK client uses. It
// must be the safehttp client: every outbound call goes through the SSRF guard.
func WithHTTPClient(c *http.Client) SinkOption { return func(o *sinkOptions) { o.httpClient = c } }

// WithS3Client injects the S3 client (tests); it replaces the SDK client that
// WithHTTPClient would build.
func WithS3Client(c S3API) SinkOption { return func(o *sinkOptions) { o.s3 = c } }

// NewSink returns the sink for a TESSERA_AUDIT_ANCHOR URL: file:///path (or
// file://relative/path) appends to a JSONL file; s3://bucket/prefix is the
// production sink (S3 Object Lock, compliance mode), which needs
// WithHTTPClient (the safehttp client) or WithS3Client. An empty URL means no
// anchoring.
func NewSink(anchorURL string, opts ...SinkOption) (Sink, error) {
	var o sinkOptions
	for _, opt := range opts {
		opt(&o)
	}
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
		client := o.s3
		if client == nil {
			if o.httpClient == nil {
				return nil, errors.New("audit: the s3:// anchor sink needs the safehttp client (every outbound call goes through it)")
			}
			var err error
			if client, err = NewS3Client(context.Background(), o.httpClient); err != nil {
				return nil, fmt.Errorf("audit: s3 anchor client: %w", err)
			}
		}
		return NewS3Sink(anchorURL, client)
	case strings.HasPrefix(anchorURL, "azure://") || strings.HasPrefix(anchorURL, "gs://"):
		if o.obj == nil {
			return nil, errors.New("audit: the azure:// and gs:// anchor sinks need the safehttp client and workload credentials (WithObjectStores)")
		}
		return NewObjectSink(anchorURL, *o.obj)
	}
	return nil, fmt.Errorf("audit: unsupported anchor URL %q (want file://, s3://, azure:// or gs://)", anchorURL)
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

// ---------------------------------------------------------------- S3 Object Lock sink

// S3API is the part of the AWS SDK for Go v2 *s3.Client that the sink uses, so
// tests (and callers with their own client) can pass a stub.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

// NewS3Client builds the AWS SDK for Go v2 S3 client with all of its HTTP
// traffic on hc, which must be the safehttp client (SSRF guard). Credentials
// and the region come from the SDK's default chain (environment, shared
// config, web identity / IRSA); the SDK's metadata-service lookups go through
// hc too, so link-local metadata endpoints are blocked by safehttp: use
// environment credentials or a web identity role.
func NewS3Client(ctx context.Context, hc *http.Client) (S3API, error) {
	if hc == nil {
		return nil, errors.New("audit: NewS3Client needs an HTTP client")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}

// S3RetentionYears is how long an anchored checkpoint is locked (design §13.6).
const S3RetentionYears = 7

var (
	s3Bucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3TID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ParseS3URL splits s3://bucket/prefix. The prefix may be empty; it never has
// a leading or trailing slash, an empty segment, "." or "..".
func ParseS3URL(anchorURL string) (bucket, prefix string, err error) {
	u, err := url.Parse(anchorURL)
	if err != nil || u.Scheme != "s3" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("audit: %q is not an s3://bucket/prefix URL", anchorURL)
	}
	if !s3Bucket.MatchString(u.Host) {
		return "", "", fmt.Errorf("audit: invalid S3 bucket name %q", u.Host)
	}
	prefix = strings.Trim(u.Path, "/")
	if prefix != "" {
		if len(prefix) > 512 {
			return "", "", errors.New("audit: S3 prefix too long")
		}
		for _, seg := range strings.Split(prefix, "/") {
			if seg == "" || seg == "." || seg == ".." || strings.ContainsFunc(seg, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return "", "", fmt.Errorf("audit: invalid S3 prefix %q", prefix)
			}
		}
	}
	return u.Host, prefix, nil
}

// S3Sink stores one object per checkpoint at <prefix>/<tid>/<seq>.jws in a
// bucket with Object Lock enabled (design §13.6). Each object is written in
// COMPLIANCE mode, retained for S3RetentionYears, with If-None-Match: * so an
// existing object is never replaced, and a SHA-256 checksum so S3 verifies the
// body. anchor_ref is the object URL with its version id, which proves the
// bucket is versioned (Object Lock requires it).
type S3Sink struct {
	Bucket, Prefix string
	Client         S3API
	// Now is the clock for the retention date (default time.Now).
	Now func() time.Time
}

// NewS3Sink returns the sink for an s3://bucket/prefix URL.
func NewS3Sink(anchorURL string, client S3API) (*S3Sink, error) {
	if client == nil {
		return nil, errors.New("audit: the S3 anchor sink needs a client")
	}
	bucket, prefix, err := ParseS3URL(anchorURL)
	if err != nil {
		return nil, err
	}
	return &S3Sink{Bucket: bucket, Prefix: prefix, Client: client}, nil
}

// Key is the object key of an anchor.
func (s *S3Sink) Key(a Anchor) (string, error) {
	if !s3TID.MatchString(a.TID) || a.Seq < 1 {
		return "", fmt.Errorf("audit: cannot anchor tid %q seq %d", a.TID, a.Seq)
	}
	k := a.TID + "/" + strconv.FormatInt(a.Seq, 10) + ".jws"
	if s.Prefix != "" {
		k = s.Prefix + "/" + k
	}
	return k, nil
}

// Anchor stores a.JWS and returns "s3://bucket/key?versionId=<id>". If the
// object already exists with the same checksum (an earlier attempt whose
// response was lost), that object's version is returned; different content
// under the same key is an error.
func (s *S3Sink) Anchor(ctx context.Context, a Anchor) (string, error) {
	if s.Client == nil {
		return "", errors.New("audit: the S3 anchor sink has no client")
	}
	key, err := s.Key(a)
	if err != nil {
		return "", err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	body := []byte(a.JWS)
	sum := sha256.Sum256(body)
	sum64 := base64.StdEncoding.EncodeToString(sum[:])
	out, err := s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:                    aws.String(s.Bucket),
		Key:                       aws.String(key),
		Body:                      bytes.NewReader(body),
		ContentType:               aws.String("application/jose"),
		ChecksumSHA256:            aws.String(sum64),
		IfNoneMatch:               aws.String("*"),
		ObjectLockMode:            s3types.ObjectLockModeCompliance,
		ObjectLockRetainUntilDate: aws.Time(now().UTC().AddDate(S3RetentionYears, 0, 0)),
		Metadata:                  map[string]string{"tid": a.TID, "seq": strconv.FormatInt(a.Seq, 10), "head-hash": a.HeadHash},
	})
	var version string
	switch {
	case err == nil:
		version = aws.ToString(out.VersionId)
	case isS3PreconditionFailed(err):
		h, herr := s.Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(s.Bucket), Key: aws.String(key), ChecksumMode: s3types.ChecksumModeEnabled})
		if herr != nil {
			return "", fmt.Errorf("audit: s3 anchor %s exists and cannot be read: %w", key, herr)
		}
		if aws.ToString(h.ChecksumSHA256) != sum64 {
			return "", fmt.Errorf("audit: s3 anchor %s already holds different content", key)
		}
		version = aws.ToString(h.VersionId)
	default:
		return "", fmt.Errorf("audit: s3 anchor %s: %w", key, err)
	}
	if version == "" {
		return "", fmt.Errorf("audit: s3 anchor %s has no version id: the bucket must be versioned with Object Lock enabled", key)
	}
	return "s3://" + s.Bucket + "/" + key + "?versionId=" + url.QueryEscape(version), nil
}

// isS3PreconditionFailed reports HTTP 412 / PreconditionFailed (If-None-Match
// found the object) and the 409 ConditionalRequestConflict of a racing write.
func isS3PreconditionFailed(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "PreconditionFailed", "ConditionalRequestConflict":
			return true
		}
	}
	var re *awshttp.ResponseError
	return errors.As(err, &re) && re.HTTPStatusCode() == http.StatusPreconditionFailed
}

// AnchorSet is the content of an anchor source, for verification.
type AnchorSet struct {
	byKey    map[string][]string // tid|seq -> JWSs (a reseeded dev database can reuse a seq)
	byTenant map[string][]Anchor // tid -> anchors, in file order
	Lines    int
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

// ForTenant returns the anchors of tid, in the order they were anchored.
func (s *AnchorSet) ForTenant(tid string) []Anchor { return s.byTenant[tid] }

// Upto keeps only the anchors at or below each tenant's head seq (tenants
// not in heads are dropped). Verifying a restored backup against the live
// anchor source needs this: checkpoints anchored after the backup was taken
// would otherwise read as truncation.
func (s *AnchorSet) Upto(heads map[string]int64) *AnchorSet {
	out := &AnchorSet{byKey: map[string][]string{}, byTenant: map[string][]Anchor{}, Lines: s.Lines}
	for tid, as := range s.byTenant {
		head, ok := heads[tid]
		if !ok {
			continue
		}
		for _, a := range as {
			if a.Seq <= head {
				k := anchorKey(a.TID, a.Seq)
				out.byKey[k] = append(out.byKey[k], a.JWS)
				out.byTenant[tid] = append(out.byTenant[tid], a)
			}
		}
	}
	return out
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
	s := &AnchorSet{byKey: map[string][]string{}, byTenant: map[string][]Anchor{}}
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
		s.byTenant[a.TID] = append(s.byTenant[a.TID], a)
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
	// OnTenant, when set, is called after each tenant's turn with what it did
	// (job run history, issue #172).
	OnTenant func(ctx context.Context, t store.Tenant, started, finished time.Time, created bool, anchored, failed int, err error)
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
		started := clock()
		created, a, f, err := c.runTenant(ctx, t, clock, force, loadKey, &key, log)
		if c.OnTenant != nil {
			c.OnTenant(ctx, t, started, clock(), created, a, f, err)
		}
		if created {
			res.Created++
		}
		res.Anchored += a
		res.Failed += f
		if errors.Is(err, errCheckpointKey) {
			return res, err
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
		}
	}
	return res, errors.Join(errs...)
}

var errCheckpointKey = errors.New("audit: checkpoint key")

// runTenant is one tenant's turn: create a checkpoint when due, then anchor
// pending ones.
func (c *Checkpointer) runTenant(ctx context.Context, t store.Tenant, clock timeutil.Clock, force bool, loadKey func() error,
	key **keys.SigningKey, log *slog.Logger) (created bool, anchored, failed int, err error) {
	due, err := c.due(ctx, t.ID, clock(), force)
	if err != nil {
		return false, 0, 0, err
	}
	if due {
		if err := loadKey(); err != nil {
			return false, 0, 0, fmt.Errorf("%w: %w", errCheckpointKey, err)
		}
		if err := c.create(ctx, t, *key, clock()); err != nil {
			return false, 0, 0, err
		}
		created = true
	}
	anchored, failed, err = c.anchorPending(ctx, t, clock(), log)
	return created, anchored, failed, err
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

// CheckpointLoopName is the checkpointer's name in obs.DefaultLoops.
const CheckpointLoopName = "audit_checkpoint"

// Loop runs Run every interval until ctx ends.
func (c *Checkpointer) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	obs.DefaultLoops.Register(CheckpointLoopName, interval, true)
	for {
		if err := obs.DefaultLoops.Run(CheckpointLoopName, func() error { _, err := c.Run(ctx, false); return err }); err != nil && ctx.Err() == nil {
			log.Error("audit checkpoint run failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
