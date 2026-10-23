package objstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// GCS is a Google Cloud Storage bucket, through the JSON API.
type GCS struct {
	T *Target
	D Deps
}

const gcsScope = "https://www.googleapis.com/auth/devstorage.read_write"

// Location implements Store.
func (g *GCS) Location() string { return g.T.String() }

func (g *GCS) base() string {
	if g.T.Endpoint != "" {
		return g.T.Endpoint
	}
	return "https://storage.googleapis.com"
}

func (g *GCS) do(ctx context.Context, method, rawURL string, body []byte, ct string) (*http.Response, error) {
	tok, err := g.D.GCP.Token(ctx, gcsScope)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	return g.D.HTTP.Do(req)
}

// Put implements Store. The upload is create-only (ifGenerationMatch=0); the
// reference is "<key>#<generation>". Retention is a property of the bucket
// (a locked retention policy), not of the request.
func (g *GCS) Put(ctx context.Context, key string, data []byte, o PutOptions) (string, error) {
	k, err := g.T.key(key)
	if err != nil {
		return "", err
	}
	u := g.base() + "/upload/storage/v1/b/" + g.T.Bucket + "/o?uploadType=media&ifGenerationMatch=0&name=" + url.QueryEscape(k)
	resp, err := g.do(ctx, http.MethodPost, u, data, orDefault(o.ContentType))
	if err != nil {
		return "", fmt.Errorf("objstore: gcs put: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed:
		return "", ErrExists
	case resp.StatusCode/100 != 2:
		return "", fmt.Errorf("objstore: gcs put: %s", resp.Status)
	}
	var meta struct {
		Generation string `json:"generation"`
	}
	_ = json.Unmarshal(b, &meta)
	return k + "#" + meta.Generation, nil
}

// Get implements Store.
func (g *GCS) Get(ctx context.Context, key string) ([]byte, error) {
	k, err := g.T.key(key)
	if err != nil {
		return nil, err
	}
	u := g.base() + "/storage/v1/b/" + g.T.Bucket + "/o/" + url.PathEscape(k) + "?alt=media"
	resp, err := g.do(ctx, http.MethodGet, u, nil, "")
	if err != nil {
		return nil, fmt.Errorf("objstore: gcs get: %w", unwrapURL(err))
	}
	return readBody(resp, "gcs get")
}

// VerifyRetention implements Verifier: the bucket must carry a locked
// retention policy (a locked policy can no longer be shortened or removed).
// A caller without storage.buckets.get gets nil: the setting cannot be read,
// and the audit anchor's own writes still work.
func (g *GCS) VerifyRetention(ctx context.Context) error {
	resp, err := g.do(ctx, http.MethodGet, g.base()+"/storage/v1/b/"+g.T.Bucket+"?fields=retentionPolicy", nil, "")
	if err != nil {
		return fmt.Errorf("objstore: gcs bucket: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusForbidden {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("objstore: gcs bucket: %s", resp.Status)
	}
	var m struct {
		RetentionPolicy *struct {
			IsLocked bool `json:"isLocked"`
		} `json:"retentionPolicy"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return errors.New("objstore: gcs bucket: unexpected response")
	}
	if m.RetentionPolicy == nil || !m.RetentionPolicy.IsLocked {
		return errors.New("objstore: the GCS bucket has no locked retention policy (set one and lock it: gcloud storage buckets update --retention-period=… --lock-retention-period)")
	}
	return nil
}
