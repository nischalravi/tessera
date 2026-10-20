// Package sigv4 signs HTTP requests with AWS Signature Version 4, using only
// the standard library (Tessera has no AWS SDK). It is what the AWS IAM
// Identity Center revoker (internal/containment) uses to call AWS
// Organizations, the identity store and sso-admin.
//
// The signer is checked against vectors of AWS's published SigV4 test suite
// (testdata/suite.json). It signs for the JSON-protocol services Tessera
// calls: the payload hash goes into the canonical request only, and the path
// is URI-encoded once more than it is on the wire, as every service but S3
// requires.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Algorithm is the only signing algorithm.
const Algorithm = "AWS4-HMAC-SHA256"

// Credentials are the signer's AWS credentials. SessionToken is set for
// temporary credentials (STS) and is then sent as X-Amz-Security-Token and signed.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// unsigned are headers a signature never covers: they are added or rewritten
// by proxies and the HTTP client after signing.
var unsigned = map[string]bool{
	"authorization": true, "user-agent": true, "x-amzn-trace-id": true, "connection": true, "expect": true,
	"accept-encoding": true, "content-length": true, "transfer-encoding": true,
}

// Sign signs req in place: it sets X-Amz-Date (and X-Amz-Security-Token for
// temporary credentials) and the Authorization header. body is the payload
// (nil for none). Every header on req but those in unsigned is signed, so set
// the others (Content-Type, X-Amz-Target) before calling Sign.
func Sign(req *http.Request, body []byte, c Credentials, region, service string, now time.Time) error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("sigv4: no credentials")
	}
	if region == "" || service == "" {
		return errors.New("sigv4: region and service are required")
	}
	now = now.UTC()
	date, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", stamp)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	creq, signed := CanonicalRequest(req, body)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sts := StringToSign(stamp, scope, creq)
	key := signingKey(c.SecretAccessKey, date, region, service)
	sig := hex.EncodeToString(hmacSHA256(key, []byte(sts)))
	req.Header.Set("Authorization", Algorithm+" Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
	return nil
}

// StringToSign is the string that is signed.
func StringToSign(stamp, scope, canonicalRequest string) string {
	return Algorithm + "\n" + stamp + "\n" + scope + "\n" + hashHex([]byte(canonicalRequest))
}

// CanonicalRequest returns the canonical request of req and the list of
// signed header names (semicolon separated).
func CanonicalRequest(req *http.Request, body []byte) (string, string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host = stripDefaultPort(host, req.URL.Scheme)
	headers := map[string][]string{"host": {host}}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if unsigned[lk] || lk == "host" {
			continue
		}
		headers[lk] = append(headers[lk], vs...)
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		vals := make([]string, len(headers[k]))
		for i, v := range headers[k] {
			vals[i] = strings.Join(strings.Fields(v), " ")
		}
		ch.WriteString(k + ":" + strings.Join(vals, ",") + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.Join([]string{req.Method, uriEncode(path, false), canonicalQuery(req.URL.RawQuery), ch.String(), signed,
		hashHex(body)}, "\n"), signed
}

func stripDefaultPort(host, scheme string) string {
	if scheme == "https" {
		return strings.TrimSuffix(host, ":443")
	}
	if scheme == "http" {
		return strings.TrimSuffix(host, ":80")
	}
	return host
}

func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			v = dv
		}
		pairs = append(pairs, kv{uriEncode(k, true), uriEncode(v, true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// uriEncode percent-encodes every byte but the unreserved characters
// (A-Z a-z 0-9 - _ . ~) and, unless encodeSlash, "/".
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~',
			c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		}
	}
	return b.String()
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
