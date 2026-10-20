package sinks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4-create-signed-request.html),
// with the standard library only. It signs the request as a header-based
// signature: host, content-type, x-amz-date, x-amz-target and
// x-amz-security-token (when present) are signed, with the SHA-256 of the body.

type awsKeys struct {
	AccessKeyID, SecretAccessKey, SessionToken string
}

// signV4 adds X-Amz-Date, X-Amz-Security-Token (temporary keys) and
// Authorization to req, which carries body. region and service name the
// credential scope.
func signV4(req *http.Request, body []byte, k awsKeys, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if k.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", k.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	signed := []string{"host"}
	vals := map[string]string{"host": host}
	for _, h := range []string{"Content-Type", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Target"} {
		if v := req.Header.Get(h); v != "" {
			n := strings.ToLower(h)
			signed = append(signed, n)
			vals[n] = strings.Join(strings.Fields(v), " ")
		}
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, n := range signed {
		canonHeaders.WriteString(n + ":" + vals[n] + "\n")
	}
	signedHeaders := strings.Join(signed, ";")

	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{req.Method, canonicalPath(req.URL.Path), canonicalQuery(req), canonHeaders.String(), signedHeaders,
		hex.EncodeToString(sum[:])}, "\n")

	scope := day + "/" + region + "/" + service + "/aws4_request"
	csum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(csum[:])

	sig := hex.EncodeToString(hmacSHA256(signingKey(k.SecretAccessKey, day, region, service), toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+k.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+sig)
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

// canonicalPath is the URI-encoded path; services other than S3 encode each
// segment twice.
func canonicalPath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = awsEncode(awsEncode(s))
	}
	return strings.Join(segs, "/")
}

func canonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEncode(k)+"="+awsEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// awsEncode percent-encodes everything but the unreserved characters.
func awsEncode(s string) string {
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
