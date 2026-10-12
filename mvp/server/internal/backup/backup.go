// Package backup takes online, encrypted snapshots of the database and
// restores them only after the audit hash chain and its anchors verify
// (issue #171, docs/runbooks/disaster-recovery.md).
//
// A backup file is:
//
//	TESSERA-BACKUP v1\n
//	<manifest JSON>\n
//	chunk*: uint32 big-endian length, then seal.Sealer.Seal(plaintext chunk, aad)
//
// The plaintext is a VACUUM INTO copy of the database, cut into ChunkSize
// pieces. Each chunk's AAD binds the backup id, the SHA-256 of the manifest
// line, the chunk index and whether it is the last chunk, so editing the
// manifest, reordering, dropping or appending chunks, or truncating the file
// all fail decryption. The manifest also carries the SHA-256 of the whole
// plaintext and every tenant's audit chain head at snapshot time.
package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

const (
	magic = "TESSERA-BACKUP v1\n"
	// Format and Version name the manifest format.
	Format  = "tessera-backup"
	Version = 1
	// ChunkSize is the plaintext size of each sealed chunk.
	ChunkSize = 1 << 20
	// Ext is the backup file extension.
	Ext = ".tbak"
	// maxManifest caps the manifest line.
	maxManifest = 1 << 20
)

// TenantHead is a tenant's audit chain head when the backup was taken.
type TenantHead struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	HeadSeq  int64  `json:"head_seq"`
	HeadHash string `json:"head_hash"`
}

// Manifest describes a backup. It is stored in clear (it holds no secret)
// and authenticated by every chunk.
type Manifest struct {
	Format    string       `json:"format"`
	Version   int          `json:"version"`
	ID        string       `json:"id"`
	CreatedAt time.Time    `json:"created_at"`
	Env       string       `json:"env"`
	Instance  string       `json:"instance,omitempty"`
	Size      int64        `json:"size"`   // plaintext bytes
	SHA256    string       `json:"sha256"` // of the plaintext
	Chunks    int          `json:"chunks"`
	KEKCheck  string       `json:"kek_check"` // derived from the KEK: tells a wrong KEK from a damaged file
	Tenants   []TenantHead `json:"tenants"`
}

// Error is a refusal with a stable code.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// kekCheck is a short value derived from the KEK, never the KEK itself.
func kekCheck(s *seal.Sealer) (string, error) {
	k, err := s.DeriveKey("tessera-backup-kek-check-v1", 8)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

func chunkAAD(id, manifestHash string, i int, last bool) []byte {
	l := "0"
	if last {
		l = "1"
	}
	return []byte("tessera-backup|v1|" + id + "|" + manifestHash + "|" + strconv.Itoa(i) + "|" + l)
}

// CreateOptions configure a backup.
type CreateOptions struct {
	Dir      string // where the backup file is written (created 0700 if missing)
	Env      string
	Instance string
	Now      time.Time
}

// Created is a written backup.
type Created struct {
	Path     string
	Manifest Manifest
}

// Create snapshots db (online; writers are not blocked for longer than
// SQLite's VACUUM INTO read transaction) and writes an encrypted backup to
// opts.Dir. The plaintext copy exists only for the duration of the call, in
// opts.Dir with mode 0600, and is removed before Create returns.
func Create(ctx context.Context, db *store.DB, sealer *seal.Sealer, opts CreateOptions) (*Created, error) {
	if sealer == nil {
		return nil, errors.New("backup: no KEK sealer")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	id := strings.ToLower(seal.RandomString(12, "abcdefghijklmnopqrstuvwxyz0123456789"))
	stamp := opts.Now.UTC().Format("20060102T150405Z")
	plain := filepath.Join(opts.Dir, ".snapshot-"+id+".db")
	defer removeDB(plain)
	if err := db.Snapshot(ctx, plain); err != nil {
		return nil, err
	}
	if err := os.Chmod(plain, 0o600); err != nil {
		return nil, err
	}
	heads, err := Heads(ctx, plain)
	if err != nil {
		return nil, fmt.Errorf("backup: the snapshot does not open: %w", err)
	}
	check, err := kekCheck(sealer)
	if err != nil {
		return nil, err
	}
	sum, size, err := fileSHA256(plain)
	if err != nil {
		return nil, err
	}
	m := Manifest{Format: Format, Version: Version, ID: id, CreatedAt: opts.Now.UTC(), Env: opts.Env, Instance: opts.Instance,
		Size: size, SHA256: sum, Chunks: chunks(size), KEKCheck: check, Tenants: heads}
	final := filepath.Join(opts.Dir, "tessera-"+stamp+"-"+id+Ext)
	part := final + ".part"
	if err := encrypt(plain, part, m, sealer); err != nil {
		_ = os.Remove(part)
		return nil, err
	}
	if err := os.Rename(part, final); err != nil {
		_ = os.Remove(part)
		return nil, err
	}
	return &Created{Path: final, Manifest: m}, nil
}

func chunks(size int64) int {
	if size == 0 {
		return 1
	}
	return int((size + ChunkSize - 1) / ChunkSize)
}

// removeDB removes a SQLite file and its WAL and shared-memory files.
func removeDB(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Remove(p)
	}
}

func fileSHA256(path string) (string, int64, error) {
	fh, err := os.Open(path) // #nosec G304 -- a path this package created
	if err != nil {
		return "", 0, err
	}
	defer fh.Close()
	h := sha256.New()
	n, err := io.Copy(h, fh)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// Heads reads every tenant's audit chain head from the database at path.
func Heads(ctx context.Context, path string) ([]TenantHead, error) {
	st, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	var tenants []store.Tenant
	if err := st.InSystem(ctx, "backup: tenants", func(s *store.SystemTx) error {
		var err error
		tenants, err = s.Tenants()
		return err
	}); err != nil {
		return nil, err
	}
	out := make([]TenantHead, 0, len(tenants))
	for _, t := range tenants {
		var h store.AuditChainHead
		if err := st.ReadTenant(ctx, t.ID, func(tx *store.TenantTx) error {
			var err error
			h, err = tx.AuditHead()
			if errors.Is(err, store.ErrNotFound) {
				err = nil
			}
			return err
		}); err != nil {
			return nil, err
		}
		out = append(out, TenantHead{ID: t.ID.String(), Slug: t.Slug, HeadSeq: h.LastSeq, HeadHash: h.LastHash})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, st.Checkpoint(ctx)
}

func encrypt(plainPath, outPath string, m Manifest, sealer *seal.Sealer) error {
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	mh := sha256.Sum256(line)
	mhex := hex.EncodeToString(mh[:])
	in, err := os.Open(plainPath) // #nosec G304 -- a path this package created
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator backup dir
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	if _, err := w.WriteString(magic); err != nil {
		_ = out.Close()
		return err
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		_ = out.Close()
		return err
	}
	buf := make([]byte, ChunkSize)
	for i := 0; i < m.Chunks; i++ {
		n, rerr := io.ReadFull(in, buf)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			_ = out.Close()
			return rerr
		}
		sealed, err := sealer.Seal(buf[:n], chunkAAD(m.ID, mhex, i, i == m.Chunks-1))
		if err != nil {
			_ = out.Close()
			return err
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(sealed))) // #nosec G115 -- a sealed chunk is ChunkSize plus a small overhead
		if _, err := w.Write(l[:]); err != nil {
			_ = out.Close()
			return err
		}
		if _, err := w.Write(sealed); err != nil {
			_ = out.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// ReadManifest reads a backup's manifest without decrypting it. The manifest
// is only authenticated by Decrypt.
func ReadManifest(path string) (Manifest, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator-supplied backup path
	if err != nil {
		return Manifest{}, err
	}
	defer fh.Close()
	m, _, _, err := readHeader(bufio.NewReader(fh))
	return m, err
}

func readHeader(r *bufio.Reader) (Manifest, string, []byte, error) {
	var m Manifest
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(r, head); err != nil || string(head) != magic {
		return m, "", nil, refuse("not_a_backup", "the file is not a Tessera backup")
	}
	line, err := r.ReadSlice('\n')
	if err != nil || len(line) > maxManifest {
		return m, "", nil, refuse("invalid_backup", "the backup manifest is unreadable")
	}
	line = append([]byte(nil), line[:len(line)-1]...)
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, "", nil, refuse("invalid_backup", "the backup manifest is not valid: %v", err)
	}
	if m.Format != Format || m.Version != Version {
		return m, "", nil, refuse("unsupported_backup", "backup format %s v%d is not supported", m.Format, m.Version)
	}
	if m.Chunks < 1 || m.Size < 0 || int64(m.Chunks) != int64(chunks(m.Size)) {
		return m, "", nil, refuse("invalid_backup", "the backup manifest is inconsistent")
	}
	mh := sha256.Sum256(line)
	return m, hex.EncodeToString(mh[:]), line, nil
}

// Decrypt authenticates and decrypts the backup at path into outPath (mode
// 0600, must not exist) and checks the plaintext against the manifest.
func Decrypt(path, outPath string, sealer *seal.Sealer) (Manifest, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator-supplied backup path
	if err != nil {
		return Manifest{}, err
	}
	defer fh.Close()
	r := bufio.NewReader(fh)
	m, mhex, _, err := readHeader(r)
	if err != nil {
		return m, err
	}
	check, err := kekCheck(sealer)
	if err != nil {
		return m, err
	}
	if check != m.KEKCheck {
		return m, refuse("wrong_kek", "this backup was sealed under a different KEK; restore with the KEK of the instance that took it")
	}
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- restore target chosen by the operator
	if err != nil {
		return m, err
	}
	h := sha256.New()
	w := io.MultiWriter(out, h)
	var total int64
	fail := func(e error) (Manifest, error) {
		_ = out.Close()
		_ = os.Remove(outPath)
		return m, e
	}
	maxSealed := uint32(ChunkSize + 1024)
	for i := 0; i < m.Chunks; i++ {
		var l [4]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return fail(refuse("tampered_backup", "the backup is truncated (chunk %d of %d missing)", i+1, m.Chunks))
		}
		n := binary.BigEndian.Uint32(l[:])
		if n == 0 || n > maxSealed {
			return fail(refuse("tampered_backup", "chunk %d has an invalid length", i+1))
		}
		sealed := make([]byte, n)
		if _, err := io.ReadFull(r, sealed); err != nil {
			return fail(refuse("tampered_backup", "the backup is truncated inside chunk %d", i+1))
		}
		pt, err := sealer.Open(sealed, chunkAAD(m.ID, mhex, i, i == m.Chunks-1))
		if err != nil {
			return fail(refuse("tampered_backup", "chunk %d does not authenticate: the backup or its manifest was changed", i+1))
		}
		if _, err := w.Write(pt); err != nil {
			return fail(err)
		}
		total += int64(len(pt))
	}
	if _, err := r.ReadByte(); !errors.Is(err, io.EOF) {
		return fail(refuse("tampered_backup", "the backup has data after its last chunk"))
	}
	if total != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return fail(refuse("tampered_backup", "the decrypted database does not match the manifest checksum"))
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	return m, out.Close()
}

// Prune keeps the newest keep backups in dir and removes the rest. keep < 1
// keeps everything. It returns the removed paths.
func Prune(dir string, keep int) ([]string, error) {
	if keep < 1 {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "tessera-") && strings.HasSuffix(e.Name(), Ext) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // the UTC timestamp in the name sorts chronologically
	var removed []string
	for len(names) > keep {
		p := filepath.Join(dir, names[0])
		if err := os.Remove(p); err != nil {
			return removed, err
		}
		removed = append(removed, p)
		names = names[1:]
	}
	return removed, nil
}
