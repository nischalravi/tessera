package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// S3 writes each batch as one object in an S3-compatible bucket (AWS S3,
// MinIO, Cloudflare R2, Wasabi, ...). Target is the bucket URL with an
// optional key prefix, path style ("https://s3.eu-west-1.amazonaws.com/audit/tessera")
// or virtual-hosted ("https://audit.s3.eu-west-1.amazonaws.com/tessera").
//
// The object key is derived from the batch's first and last seq, so a batch
// that is sent again after a failure replaces the same object instead of
// adding a copy: delivery stays at least once and the bucket has no duplicates.
// Requests are signed with AWS Signature Version 4 (stdlib only) and go out
// through the guarded client of internal/safehttp.
type S3 struct {
	Client      *http.Client
	Target      string
	Region      string
	AccessKeyID string
	Secret      string
	Tenant      string // key prefix: the tenant slug
	Format      string
	Now         func() time.Time
}

// Key is the object key (below Target) of a batch.
func (s *S3) Key(batch []Record) string {
	first, last := batch[0], batch[len(batch)-1]
	ext := "ndjson"
	if s.Format == FormatOCSF {
		ext = "ocsf.ndjson"
	}
	return fmt.Sprintf("%s/%s/%012d-%012d.%s", s.Tenant, first.OccurredAt.UTC().Format("2006/01/02"), first.Seq, last.Seq, ext)
}

// Body is the object content: one JSON event per line.
func (s *S3) Body(batch []Record) []byte {
	var b bytes.Buffer
	for _, r := range batch {
		b.Write(r.Payload)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func (s *S3) objectURL(key string) (string, error) {
	u, err := url.Parse(s.Target)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad bucket URL")
	}
	base := strings.TrimRight(u.EscapedPath(), "/")
	segs := strings.Split(key, "/")
	for i, g := range segs {
		segs[i] = awsEscape(g)
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
	return u.String() + base + "/" + strings.Join(segs, "/"), nil
}

// Send puts the batch as one object.
func (s *S3) Send(ctx context.Context, batch []Record) error {
	if s.Client == nil {
		return retryable("s3 delivery is not configured")
	}
	if len(batch) == 0 {
		return nil
	}
	target, err := s.objectURL(s.Key(batch))
	if err != nil {
		return &SendError{Permanent: true, Msg: "bad bucket URL"}
	}
	body := s.Body(batch)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return &SendError{Permanent: true, Msg: "bad bucket URL"}
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("User-Agent", "Tessera-SIEM/1")
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	SignV4(req, body, s.Region, "s3", s.AccessKeyID, s.Secret, now)
	resp, err := s.Client.Do(req)
	if err != nil {
		return retryable("s3: %s", safehttp.ScrubError(err, s.Target))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return retryable("s3: HTTP %d", resp.StatusCode)
	default:
		return &SendError{Permanent: true, Msg: fmt.Sprintf("s3: HTTP %d (check the bucket, region and access key)", resp.StatusCode)}
	}
}

// awsEscape percent-encodes everything but the unreserved characters (AWS's
// UriEncode, without the slash exception).
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// signedHeader reports whether a header takes part in the signature: the host,
// the content type and checksum, the date and every x-amz-* header.
func signedHeader(name string) bool {
	switch name {
	case "host", "content-type", "content-md5", "date":
		return true
	}
	return strings.HasPrefix(name, "x-amz-")
}

// SignV4 signs req with AWS Signature Version 4 (header form) for service in
// region and sets its Authorization, X-Amz-Date and X-Amz-Content-Sha256
// headers. body is the request payload (nil for none). The path of req.URL is
// used as it is encoded in req.URL.EscapedPath, which for S3 is also the
// canonical URI (S3 does not normalise or double-encode it).
func SignV4(req *http.Request, body []byte, region, service, keyID, secret string, now time.Time) {
	now = now.UTC()
	date, stamp := now.Format("20060102T150405Z"), now.Format("20060102")
	payload := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payload[:])
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", payloadHex)

	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	hdr := map[string]string{"host": host}
	for k, v := range req.Header {
		if n := strings.ToLower(k); signedHeader(n) {
			hdr[n] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
		}
	}
	names := make([]string, 0, len(hdr))
	for n := range hdr {
		names = append(names, n)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, n := range names {
		canon.WriteString(n + ":" + hdr[n] + "\n")
	}
	signed := strings.Join(names, ";")
	uri := req.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	creq := strings.Join([]string{req.Method, uri, req.URL.RawQuery, canon.String(), signed, payloadHex}, "\n")
	scope := stamp + "/" + region + "/" + service + "/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := hmacSHA256([]byte("AWS4"+secret), stamp)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, sts))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", keyID, scope, signed, sig))
}
