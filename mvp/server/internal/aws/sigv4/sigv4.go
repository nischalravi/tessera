// Package sigv4 signs AWS requests with Signature Version 4, using the
// standard library only (docs/design/aws-effective-permission-evaluator.md
// §11.1; the connector deliberately does not use the AWS SDK).
//
// The algorithm is the one in "Create a signed AWS API request"
// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html),
// header-based, with the SHA-256 of the body as the payload hash. The package
// does no I/O and reads no clock: the caller passes the signing time.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Credentials are the keys a request is signed with. SessionToken is set for
// temporary credentials (STS) and empty for long-term keys.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// String never reveals the secret (a Credentials value must not reach a log).
func (c Credentials) String() string { return "sigv4.Credentials{REDACTED}" }

// GoString never reveals the secret (fmt %#v).
func (c Credentials) GoString() string { return c.String() }

// Valid reports whether the keys are usable for signing.
func (c Credentials) Valid() bool { return c.AccessKeyID != "" && c.SecretAccessKey != "" }

// TimeLayout is the X-Amz-Date format.
const TimeLayout = "20060102T150405Z"

// Sign signs req in place. body is the exact request body (nil for none); the
// caller sends the same bytes. It sets X-Amz-Date, X-Amz-Security-Token (for
// temporary credentials), X-Amz-Content-Sha256 (S3 only, where AWS requires
// it) and Authorization.
//
// The signed headers are host, content-type, content-md5 and every x-amz-*
// header present when Sign is called, so set those before signing. service is
// the signing name ("iam", "s3", "organizations", ...). S3 (service "s3", which
// is also the signing name of s3control) uses a single-encoded path; every
// other service encodes it twice. The path is signed as given: callers build
// clean paths (no "." or ".." segments, no repeated slashes).
func Sign(req *http.Request, body []byte, c Credentials, region, service string, now time.Time) error {
	if !c.Valid() {
		return errors.New("sigv4: credentials are incomplete")
	}
	if region == "" || service == "" {
		return errors.New("sigv4: region and service are required")
	}
	now = now.UTC()
	amzDate := now.Format(TimeLayout)
	day := now.Format("20060102")
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])

	req.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	if service == "s3" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	vals := map[string]string{"host": host}
	for name, vs := range req.Header {
		n := strings.ToLower(name)
		if n == "content-type" || n == "content-md5" || strings.HasPrefix(n, "x-amz-") {
			vals[n] = collapse(strings.Join(vs, ","))
		}
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + vals[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonical := strings.Join([]string{req.Method, canonicalPath(req.URL.Path, service == "s3"), canonicalQuery(req),
		ch.String(), signedHeaders, payloadHash}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	csum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(csum[:])
	sig := hex.EncodeToString(hmacSHA256(signingKey(c.SecretAccessKey, day, region, service), toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
	return nil
}

func signingKey(secret, day, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// collapse trims a header value and folds runs of spaces, as the canonical
// header rules require.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// canonicalPath is the URI-encoded absolute path: each segment encoded once
// for S3 and twice for every other service.
func canonicalPath(p string, s3 bool) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		s = Encode(s)
		if !s3 {
			s = Encode(s)
		}
		segs[i] = s
	}
	return strings.Join(segs, "/")
}

// canonicalQuery sorts the encoded name=value pairs. A query parameter with no
// value ("?policy") signs as "policy=".
func canonicalQuery(req *http.Request) string {
	var pairs []string
	for k, vs := range req.URL.Query() {
		for _, v := range vs {
			pairs = append(pairs, Encode(k)+"="+Encode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// Encode percent-encodes everything except the unreserved characters
// (A-Z a-z 0-9 - _ . ~), with upper-case hex. Callers also use it to build
// query strings, so that what is signed is what is sent.
func Encode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}
