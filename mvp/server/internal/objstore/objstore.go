// Package objstore is a small, create-only blob store over the three clouds'
// object services: S3 (and S3-compatible stores), Azure Blob Storage and
// Google Cloud Storage. It backs the sealed archive segments, the backups and
// the audit anchors, which need only three things: write an object once, read
// it back, and (for anchors) lock it against deletion for a retention period.
//
// It is standard library only: S3 requests are signed with internal/aws/sigv4,
// and credentials come from the workload's identity (internal/cloudcred), not
// from stored keys. Every request goes through the *http.Client in Deps, which
// must be the SSRF-guarded client of internal/safehttp.
//
// URL forms (TESSERA_ARCHIVE_URL, TESSERA_BACKUP_URL, TESSERA_AUDIT_ANCHOR):
//
//	s3://bucket/prefix[?region=eu-west-1][&endpoint=https://s3.example.com]
//	azure://account/container/prefix[?endpoint=https://account.blob.core.windows.net][&worm=version]
//	gs://bucket/prefix
//
// Objects are never replaced: Put fails with ErrExists on a key that exists.
package objstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/cloudcred"
)

// Errors.
var (
	// ErrExists: the key already holds an object (objects are write-once).
	ErrExists = errors.New("objstore: object already exists")
	// ErrNotFound: no object under the key.
	ErrNotFound = errors.New("objstore: object not found")
)

// PutOptions are the optional attributes of a Put.
type PutOptions struct {
	ContentType string
	// RetainUntil, when set, locks the object against deletion and
	// overwrite until then (S3 Object Lock in compliance mode; Azure
	// version-level immutability in locked mode). GCS retention is a bucket
	// property: see Verifier.
	RetainUntil time.Time
	// Metadata is stored with the object where the service supports it on a
	// single-request upload (S3, Azure).
	Metadata map[string]string
}

// Store is one bucket or container with a key prefix.
type Store interface {
	// Put creates the object and returns a reference to it (a version id or
	// generation, when the service has one). It never replaces an object.
	Put(ctx context.Context, key string, data []byte, o PutOptions) (ref string, err error)
	// Get returns the object, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// Location is the store's URL without credentials, for logs and audit.
	Location() string
}

// Verifier is implemented by stores that can check, with their own
// permissions, that the bucket enforces retention (GCS bucket retention lock).
type Verifier interface {
	VerifyRetention(ctx context.Context) error
}

// Deps are what a store needs from the process.
type Deps struct {
	// HTTP is the guarded client. Required.
	HTTP  *http.Client
	AWS   *cloudcred.AWS
	Azure *cloudcred.Azure
	GCP   *cloudcred.GCP
	Now   func() time.Time
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// Target is a parsed object-store URL.
type Target struct {
	Scheme    string // s3, azure or gs
	Account   string // azure: the storage account
	Bucket    string // s3 and gs: the bucket; azure: the container
	Prefix    string // key prefix without slashes at the ends
	Region    string // s3 (optional: else from the environment)
	Endpoint  string // optional https base URL replacing the service's
	Immutable string // azure: "version" (default) sets a locked retention on each object, "container" relies on the container's own policy
}

var (
	bucketRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	accountRE = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	prefixRE  = regexp.MustCompile(`^[A-Za-z0-9._/=-]*$`)
	regionRE  = regexp.MustCompile(`^[a-z0-9-]{2,32}$`)
)

// IsObjectURL reports whether raw uses one of the object-store schemes.
func IsObjectURL(raw string) bool {
	for _, p := range []string{"s3://", "azure://", "gs://"} {
		if strings.HasPrefix(raw, p) {
			return true
		}
	}
	return false
}

// ParseURL validates an object-store URL. It has no credentials: those come
// from the workload's identity.
func ParseURL(raw string) (*Target, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || u.Host == "" {
		return nil, fmt.Errorf("objstore: %q is not a valid object-store URL", redact(raw))
	}
	t := &Target{Scheme: u.Scheme}
	path := strings.Trim(u.Path, "/")
	switch u.Scheme {
	case "s3", "gs":
		t.Bucket, t.Prefix = u.Host, path
		if !bucketRE.MatchString(t.Bucket) {
			return nil, fmt.Errorf("objstore: bad bucket name in %q", redact(raw))
		}
	case "azure":
		t.Account = u.Host
		container, prefix, _ := strings.Cut(path, "/")
		t.Bucket, t.Prefix = container, strings.Trim(prefix, "/")
		if !accountRE.MatchString(t.Account) {
			return nil, fmt.Errorf("objstore: bad storage account name in %q (want azure://account/container/prefix)", redact(raw))
		}
		if !bucketRE.MatchString(t.Bucket) {
			return nil, fmt.Errorf("objstore: bad container name in %q (want azure://account/container/prefix)", redact(raw))
		}
	default:
		return nil, fmt.Errorf("objstore: unsupported scheme %q", u.Scheme)
	}
	if !prefixRE.MatchString(t.Prefix) || strings.Contains(t.Prefix, "..") || strings.Contains(t.Prefix, "//") {
		return nil, errors.New("objstore: the key prefix may hold letters, digits and . _ - = / only")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("objstore: bad query")
	}
	allowed := map[string][]string{"s3": {"region", "endpoint"}, "azure": {"endpoint", "worm"}, "gs": {"endpoint"}}[u.Scheme]
	for k := range q {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return nil, fmt.Errorf("objstore: unknown option %q for %s:// (have %v)", k, u.Scheme, allowed)
		}
	}
	t.Region, t.Endpoint = q.Get("region"), q.Get("endpoint")
	if t.Region != "" && !regionRE.MatchString(t.Region) {
		return nil, errors.New("objstore: bad region")
	}
	if t.Endpoint != "" {
		eu, err := url.Parse(t.Endpoint)
		if err != nil || (eu.Scheme != "https" && eu.Scheme != "http") || eu.Host == "" || eu.User != nil || eu.RawQuery != "" || eu.Fragment != "" {
			return nil, errors.New("objstore: endpoint must be an http(s) URL without credentials or query")
		}
		t.Endpoint = strings.TrimRight(t.Endpoint, "/")
	}
	switch w := q.Get("worm"); w {
	case "", "version":
		t.Immutable = "version"
	case "container":
		t.Immutable = "container"
	default:
		return nil, errors.New("objstore: worm must be version or container")
	}
	return t, nil
}

func redact(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Redacted()
	}
	return "(unparseable)"
}

// String is the URL without query.
func (t *Target) String() string {
	switch t.Scheme {
	case "azure":
		return "azure://" + t.Account + "/" + strings.Trim(t.Bucket+"/"+t.Prefix, "/")
	}
	return t.Scheme + "://" + strings.Trim(t.Bucket+"/"+t.Prefix, "/")
}

// key joins the prefix and a store key, refusing anything but a clean relative path.
func (t *Target) key(k string) (string, error) {
	if k == "" || strings.HasPrefix(k, "/") || strings.Contains(k, "..") || strings.Contains(k, "//") || !prefixRE.MatchString(k) {
		return "", fmt.Errorf("objstore: invalid object key %q", k)
	}
	if t.Prefix == "" {
		return k, nil
	}
	return t.Prefix + "/" + k, nil
}

// Open returns the store for raw.
func Open(raw string, d Deps) (Store, error) {
	t, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	if d.HTTP == nil {
		return nil, errors.New("objstore: needs the safehttp client (every outbound call goes through it)")
	}
	switch t.Scheme {
	case "s3":
		if d.AWS == nil {
			return nil, errors.New("objstore: no AWS credentials source")
		}
		return &S3{T: t, D: d}, nil
	case "azure":
		if d.Azure == nil {
			return nil, errors.New("objstore: no Azure credentials source")
		}
		return &Azure{T: t, D: d}, nil
	default:
		if d.GCP == nil {
			return nil, errors.New("objstore: no GCP credentials source")
		}
		return &GCS{T: t, D: d}, nil
	}
}
