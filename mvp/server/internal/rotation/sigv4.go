package rotation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Minimal AWS Signature Version 4 (no SDK): enough to sign the IAM query API
// and the Secrets Manager JSON API. It signs host, content-type, x-amz-date,
// x-amz-target and x-amz-security-token (whichever are present), with the
// payload hash in the canonical request.

// awsCreds is an AWS credential. It is held only while a call is signed.
type awsCreds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	amzDate      = "20060102T150405Z"
)

var signedHeaderNames = []string{"content-type", "host", "x-amz-date", "x-amz-security-token", "x-amz-target"}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signV4 sets X-Amz-Date, X-Amz-Security-Token (with a session token) and
// Authorization on req, which must already carry its Content-Type and, for the
// JSON API, X-Amz-Target. body is the exact payload that will be sent.
func signV4(req *http.Request, body []byte, c awsCreds, region, service string, now time.Time) {
	now = now.UTC()
	stamp := now.Format(amzDate)
	date := stamp[:8]
	req.Header.Set("X-Amz-Date", stamp)
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	var canonHeaders, signed []string
	for _, name := range signedHeaderNames {
		var v string
		if name == "host" {
			v = host
		} else {
			v = req.Header.Get(name)
		}
		if v == "" {
			continue
		}
		canonHeaders = append(canonHeaders, name+":"+strings.Join(strings.Fields(v), " ")+"\n")
		signed = append(signed, name)
	}
	signedList := strings.Join(signed, ";")

	canonical := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL),
		canonicalQuery(req.URL.Query()),
		strings.Join(canonHeaders, ""),
		signedList,
		sha256Hex(body),
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{sigAlgorithm, stamp, scope, sha256Hex([]byte(canonical))}, "\n")

	key := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), date)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", sigAlgorithm+" Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signedList+", Signature="+sig)
}

func canonicalPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEscape(k)+"="+awsEscape(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// awsEscape is RFC 3986 percent-encoding: only unreserved characters stay.
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}
