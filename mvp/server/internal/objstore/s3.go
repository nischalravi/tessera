package objstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// S3 is an S3 bucket (or an S3-compatible service through ?endpoint=).
type S3 struct {
	T *Target
	D Deps
}

// Location implements Store.
func (s *S3) Location() string { return s.T.String() }

func (s *S3) region(ctx context.Context) (string, error) {
	if s.T.Region != "" {
		return s.T.Region, nil
	}
	if s.T.Endpoint != "" {
		return "us-east-1", nil // S3-compatible services accept any region name
	}
	return s.D.AWS.Region(ctx)
}

// objectURL is path style for a custom endpoint or a bucket name with dots
// (a wildcard certificate cannot cover it), else virtual-hosted style.
func (s *S3) objectURL(region, key string) (*url.URL, error) {
	k, err := s.T.key(key)
	if err != nil {
		return nil, err
	}
	var raw string
	switch {
	case s.T.Endpoint != "":
		raw = s.T.Endpoint + "/" + s.T.Bucket + "/" + k
	case strings.Contains(s.T.Bucket, "."):
		raw = "https://s3." + region + ".amazonaws.com/" + s.T.Bucket + "/" + k
	default:
		raw = "https://" + s.T.Bucket + ".s3." + region + ".amazonaws.com/" + k
	}
	return url.Parse(raw)
}

func (s *S3) do(ctx context.Context, method, key string, body []byte, hdr map[string]string) (*http.Response, error) {
	region, err := s.region(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.objectURL(region, key)
	if err != nil {
		return nil, err
	}
	creds, err := s.D.AWS.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if err := sigv4.Sign(req, body, creds, region, "s3", s.D.now()); err != nil {
		return nil, err
	}
	return s.D.HTTP.Do(req)
}

// Put implements Store.
func (s *S3) Put(ctx context.Context, key string, data []byte, o PutOptions) (string, error) {
	sum := sha256.Sum256(data)
	hdr := map[string]string{"Content-Type": orDefault(o.ContentType), "If-None-Match": "*",
		"x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(sum[:])}
	if !o.RetainUntil.IsZero() {
		hdr["x-amz-object-lock-mode"] = "COMPLIANCE"
		hdr["x-amz-object-lock-retain-until-date"] = o.RetainUntil.UTC().Format(time.RFC3339)
	}
	for _, k := range sortedKeys(o.Metadata) {
		hdr["x-amz-meta-"+strings.ToLower(k)] = o.Metadata[k]
	}
	resp, err := s.do(ctx, http.MethodPut, key, data, hdr)
	if err != nil {
		return "", fmt.Errorf("objstore: s3 put: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusPreconditionFailed:
		return "", ErrExists
	case resp.StatusCode/100 != 2:
		return "", fmt.Errorf("objstore: s3 put: %s", resp.Status)
	}
	return resp.Header.Get("x-amz-version-id"), nil
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, key, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("objstore: s3 get: %w", unwrapURL(err))
	}
	return readBody(resp, "s3 get")
}

func orDefault(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func unwrapURL(err error) error {
	if ue, ok := err.(*url.Error); ok {
		return ue.Err
	}
	return err
}

// readBody returns a 200 body, ErrNotFound for 404, or an error naming the status.
func readBody(resp *http.Response, what string) ([]byte, error) {
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, ErrNotFound
	case resp.StatusCode/100 != 2:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("objstore: %s: %s", what, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("objstore: %s: %w", what, err)
	}
	return b, nil
}
