package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/objstore"
)

// ObjectSink anchors checkpoints in an Azure Blob container (azure://) or a
// Google Cloud Storage bucket (gs://), the equivalents of the S3 Object Lock
// sink for deployments outside AWS. Each anchor is one create-only object
// <prefix>/<tid>/<seq>.jws:
//
//   - Azure: the container needs version-level immutability enabled
//     (time-based retention); every object is written with a locked
//     immutability policy of S3RetentionYears. With ?worm=container the
//     container's own time-based retention policy is relied on instead.
//   - GCS: the bucket needs a locked retention policy (bucket lock);
//     the sink refuses to start anchoring while the bucket reports none.
//
// Credentials come from the workload identity (internal/cloudcred).
type ObjectSink struct {
	Store objstore.Store
	// Retain is set for Azure's version-level mode: each Put carries a
	// retention date.
	Retain bool
	// Now is the clock for the retention date (default time.Now).
	Now func() time.Time

	verified bool
}

// NewObjectSink returns the sink for an azure:// or gs:// anchor URL.
func NewObjectSink(anchorURL string, deps objstore.Deps) (*ObjectSink, error) {
	t, err := objstore.ParseURL(anchorURL)
	if err != nil {
		return nil, err
	}
	if t.Scheme != "azure" && t.Scheme != "gs" {
		return nil, fmt.Errorf("audit: %q is not an azure:// or gs:// anchor URL", anchorURL)
	}
	st, err := objstore.Open(anchorURL, deps)
	if err != nil {
		return nil, err
	}
	return &ObjectSink{Store: st, Retain: t.Scheme == "azure" && t.Immutable == "version"}, nil
}

// Anchor implements Sink. It returns "<location>/<key>" plus "?versionId=<id>"
// when the service gives a version.
func (s *ObjectSink) Anchor(ctx context.Context, a Anchor) (string, error) {
	if !s3TID.MatchString(a.TID) || a.Seq < 1 {
		return "", fmt.Errorf("audit: cannot anchor tid %q seq %d", a.TID, a.Seq)
	}
	if v, ok := s.Store.(objstore.Verifier); ok && !s.verified {
		if err := v.VerifyRetention(ctx); err != nil {
			return "", fmt.Errorf("audit: anchor store: %w", err)
		}
		s.verified = true
	}
	key := a.TID + "/" + strconv.FormatInt(a.Seq, 10) + ".jws"
	opts := objstore.PutOptions{ContentType: "application/jose",
		Metadata: map[string]string{"tid": a.TID, "seq": strconv.FormatInt(a.Seq, 10), "head-hash": a.HeadHash}}
	if s.Retain {
		now := time.Now
		if s.Now != nil {
			now = s.Now
		}
		opts.RetainUntil = now().UTC().AddDate(S3RetentionYears, 0, 0)
	}
	body := []byte(a.JWS)
	ref, err := s.Store.Put(ctx, key, body, opts)
	if errors.Is(err, objstore.ErrExists) {
		// a retry whose answer was lost: fine if it holds exactly this JWS
		old, gerr := s.Store.Get(ctx, key)
		if gerr != nil || !bytes.Equal(old, body) {
			return "", fmt.Errorf("audit: anchor %s already holds different content", key)
		}
		ref, err = "", nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: anchor %s: %w", key, err)
	}
	out := s.Store.Location() + "/" + key
	if ref != "" {
		out += "?versionId=" + url.QueryEscape(ref)
	}
	return out, nil
}
