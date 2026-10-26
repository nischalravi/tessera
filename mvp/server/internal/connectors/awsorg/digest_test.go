package awsorg

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/awsreplay"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// digestSigner builds a fake CloudTrail digest chain signed the way AWS signs
// it (SHA256withRSA over end time, location, file hash and previous signature).
type digestSigner struct {
	t    *testing.T
	key  *rsa.PrivateKey
	fp   string
	prev map[string]*signedDigest // by "<account>/<region>"
}

type signedDigest struct{ key, hash, sig string }

func newDigestSigner(t *testing.T) *digestSigner {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &digestSigner{t: t, key: k, fp: "cafebabe0123456789", prev: map[string]*signedDigest{}}
}

// install serves the public key through ListPublicKeys.
func (d *digestSigner) install(e *usageEnv) {
	der, err := x509.MarshalPKIXPublicKey(&d.key.PublicKey)
	if err != nil {
		d.t.Fatal(err)
	}
	body := fmt.Sprintf(`{"PublicKeyList":[{"Value":%q,"Fingerprint":%q}]}`, base64.StdEncoding.EncodeToString(der), d.fp)
	for i := 0; i < 30; i++ {
		e.re.Enqueue("cloudtrail/ListPublicKeys", awsreplay.Response{Body: body})
	}
}

type digestOpt struct {
	listed  map[string]string // log file key -> inflated content to hash (nil: none)
	hashes  map[string]string // log file key -> hash to write instead of the true one
	signer  *rsa.PrivateKey   // sign with another key
	noSig   bool
	prevSig string // write this previous signature instead of the true one (it is still signed as written)
}

func digestKey(account, region string, end time.Time) string {
	return trailRoot + account + "/CloudTrail-Digest/" + region + "/" + end.Format("2006/01/02") + "/" +
		account + "_CloudTrail-Digest_" + region + "_org-trail_" + region + "_" + end.Format("20060102T150405Z") + ".json.gz"
}

// add writes a digest ending at end for the prefix, linked to the one before it.
func (d *digestSigner) add(e *usageEnv, account, region string, end time.Time, o digestOpt) *signedDigest {
	d.t.Helper()
	ck := account + "/" + region
	prev := d.prev[ck]
	key := digestKey(account, region, end)
	f := map[string]any{
		"awsAccountId": account, "digestStartTime": end.Add(-time.Hour).Format(time.RFC3339), "digestEndTime": end.Format(time.RFC3339),
		"digestS3Bucket": trailBucket, "digestS3Object": key, "digestPublicKeyFingerprint": d.fp, "digestSignatureAlgorithm": "SHA256withRSA",
		"previousDigestS3Object": nil, "previousDigestHashValue": nil, "previousDigestSignature": nil,
	}
	prevSig := "null"
	if prev != nil {
		f["previousDigestS3Object"], f["previousDigestHashValue"] = prev.key, prev.hash
		prevSig = prev.sig
		if o.prevSig != "" {
			prevSig = o.prevSig
		}
		f["previousDigestSignature"] = prevSig
	}
	logs := []map[string]string{}
	for k, content := range o.listed {
		sum := sha256.Sum256([]byte(content))
		h := hex.EncodeToString(sum[:])
		if w, ok := o.hashes[k]; ok {
			h = w
		}
		logs = append(logs, map[string]string{"s3Bucket": trailBucket, "s3Object": k, "hashValue": h, "hashAlgorithm": "SHA-256"})
	}
	f["logFiles"] = logs
	raw, err := json.Marshal(f)
	if err != nil {
		d.t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	signed := end.Format(time.RFC3339) + "\n" + trailBucket + "/" + key + "\n" + hash + "\n" + prevSig
	h := sha256.Sum256([]byte(signed))
	pk := d.key
	if o.signer != nil {
		pk = o.signer
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, h[:])
	if err != nil {
		d.t.Fatal(err)
	}
	sd := &signedDigest{key: key, hash: hash, sig: hex.EncodeToString(sig)}
	e.bucket.put(key, gz(d.t, string(raw)))
	if !o.noSig {
		e.bucket.sigs[key] = sd.sig
	}
	d.prev[ck] = sd
	return sd
}

const dAcct = "222222222222"

func dLogKey(stamp string) string { return trailKey(dAcct, "us-east-1", "2026-10-15", stamp) }

func dLog(h int) string {
	return logBody(roleCall(fmt.Sprintf("2026-10-15T%02d:00:00Z", h), "ec2.amazonaws.com", "RunInstances", roleDE, ""))
}

var dEnd = func(h int) time.Time { return time.Date(2026, 10, 15, h, 0, 5, 0, time.UTC) }

const dRows = " ec2:RunInstances * 2026-10-15 cloudtrail"

// putLog stores the log file for hour h and returns its key and content.
func putLog(t *testing.T, e *usageEnv, h int) (string, string) {
	k := dLogKey(fmt.Sprintf("20261015T%02d05Z", h))
	body := dLog(h)
	e.bucket.put(k, gz(t, body))
	return k, body
}

func digestGap(e *usageEnv, t *testing.T, ref, code string) *store.AWSUsageGap {
	t.Helper()
	g := e.gaps(t)["cloudtrail "+ref]
	if g == nil || g.Code != code {
		t.Fatalf("gap %s = %+v, want code %s; gaps: %v", ref, g, code, e.gaps(t))
	}
	return g
}

func TestDigest_ValidChainCountsRecords(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	s := newDigestSigner(t)
	s.install(e)
	k1, b1 := putLog(t, e, 1)
	k2, b2 := putLog(t, e, 2)
	s.add(e, dAcct, "us-east-1", dEnd(2), digestOpt{listed: map[string]string{k1: b1}})
	s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k2: b2}})
	// an hour of a digest day with no logs: the chain still has to link
	s.add(e, dAcct, "us-east-1", dEnd(4), digestOpt{})

	st := e.mustRun(t)
	if ct := st.CloudTrail; ct.Objects != 2 || ct.Refused != 0 {
		t.Fatalf("stats = %+v", ct)
	}
	if got := e.rows(t)[roleDE+dRows]; got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	for ref, g := range e.gaps(t) {
		if strings.HasPrefix(g.Code, "digest_") {
			t.Errorf("unexpected digest gap %s: %+v", ref, g)
		}
	}
	var listed bool
	for _, q := range e.re.Requests() {
		listed = listed || q.Service == "cloudtrail" && q.Operation == "ListPublicKeys"
	}
	if !listed {
		t.Error("cloudtrail:ListPublicKeys was not called")
	}
}

func TestDigest_Failures(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		wantCode string
		build    func(t *testing.T, e *usageEnv, s *digestSigner, key, body string)
		tamper   bool // the log object's bytes differ from the ones the digest hashed
	}{
		{"log file altered after the digest", "digest_invalid", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}})
		}, true},
		{"digest lists another hash", "digest_invalid", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}, hashes: map[string]string{k: strings.Repeat("0", 64)}})
		}, false},
		{"signature by another key", "digest_invalid", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}, signer: other})
		}, false},
		{"no signature in the metadata", "digest_invalid", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}, noSig: true})
		}, false},
		{"previous signature does not link", "digest_invalid", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(2), digestOpt{})
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}, prevSig: strings.Repeat("ab", 8)})
		}, false},
		{"file in no digest", "digest_missing", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{})
			s.add(e, dAcct, "us-east-1", dEnd(4), digestOpt{})
		}, false},
		{"a digest was deleted from the chain", "digest_missing", func(t *testing.T, e *usageEnv, s *digestSigner, k, b string) {
			s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}})
			gone := s.add(e, dAcct, "us-east-1", dEnd(4), digestOpt{})
			s.add(e, dAcct, "us-east-1", dEnd(5), digestOpt{})
			delete(e.bucket.objects, gone.key)
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newUsageEnv(t, trailOnly())
			s := newDigestSigner(t)
			s.install(e)
			k, b := putLog(t, e, 1)
			c.build(t, e, s, k, b)
			if c.tamper {
				e.bucket.put(k, gz(t, strings.Replace(b, "RunInstances", "RunInstancez", 1)))
			}
			st := e.mustRun(t)
			if ct := st.CloudTrail; ct.Objects != 0 || ct.Refused != 1 {
				t.Fatalf("stats = %+v: an unverified file must not be counted", ct)
			}
			if len(e.rows(t)) != 0 {
				t.Errorf("rows = %v, want none", e.rows(t))
			}
			g := digestGap(e, t, k, c.wantCode)
			if g.Day != "2026-10-15" || g.Detail == "" {
				t.Errorf("gap = %+v", g)
			}
		})
	}
}

// Validation off for the trail: no digests under the region. The records are
// counted, as before, and the gap says they are unverified.
func TestDigest_DisabledIsAnExplicitGap(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	k, _ := putLog(t, e, 1)
	k2, _ := putLog(t, e, 2)
	st := e.mustRun(t)
	if ct := st.CloudTrail; ct.Objects != 2 || ct.Refused != 0 {
		t.Fatalf("stats = %+v", ct)
	}
	if got := e.rows(t)[roleDE+dRows]; got != 2 {
		t.Errorf("count = %d", got)
	}
	g := digestGap(e, t, "digest:"+dAcct+"/us-east-1", "digest_disabled")
	if !strings.Contains(g.Detail, "validation is off") {
		t.Errorf("detail = %q", g.Detail)
	}
	if e.gaps(t)["cloudtrail "+k] != nil || e.gaps(t)["cloudtrail "+k2] != nil {
		t.Error("a per-file gap was recorded for a trail with validation off")
	}
	for _, x := range e.re.Requests() {
		if x.Operation == "ListPublicKeys" {
			t.Error("ListPublicKeys called with no digest to verify")
		}
	}
	// the gap weighs on least-privilege confidence (LP-2)
	if !strings.HasPrefix(g.Code, "digest_") {
		t.Errorf("code %q would not lower confidence", g.Code)
	}
}

// A file whose digest is not published yet waits: not counted, no gap, and the
// cursor stays before it; once the digest is out, the next run counts it.
func TestDigest_RecentFileWaitsForItsDigest(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	s := newDigestSigner(t)
	s.install(e)
	k1, b1 := putLog(t, e, 1)
	s.add(e, dAcct, "us-east-1", dEnd(2), digestOpt{listed: map[string]string{k1: b1}}) // digests exist: validation is on
	k2 := trailKey(dAcct, "us-east-1", "2026-10-16", "20261016T1100Z")                  // an hour before testNow
	b2 := logBody(roleCall("2026-10-16T11:00:00Z", "ec2.amazonaws.com", "RunInstances", roleDE, ""))
	e.bucket.put(k2, gz(t, b2))

	st := e.mustRun(t)
	if ct := st.CloudTrail; ct.Objects != 1 || ct.Refused != 0 {
		t.Fatalf("stats = %+v", ct)
	}
	for ref, g := range e.gaps(t) {
		if strings.HasPrefix(g.Code, "digest_") {
			t.Errorf("gap %s = %+v: a file awaiting its digest is not a gap", ref, g)
		}
	}
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-16 cloudtrail"]; got != 0 {
		t.Errorf("the unverified recent file was counted: %d", got)
	}
	var cur trailCursor
	if err := json.Unmarshal(e.state(t, store.AWSUsageCloudTrail).Cursor, &cur); err != nil {
		t.Fatal(err)
	}
	if got := cur.Prefixes[dAcct+"/us-east-1"]; !strings.Contains(got, "20261015T0105Z") {
		t.Errorf("cursor = %q: it passed the file awaiting its digest", got)
	}
	// the digest comes out
	s.add(e, dAcct, "us-east-1", time.Date(2026, 10, 16, 12, 0, 5, 0, time.UTC), digestOpt{listed: map[string]string{k2: b2}})
	e.mustRun(t)
	if got := e.rows(t)[roleDE+" ec2:RunInstances * 2026-10-16 cloudtrail"]; got != 1 {
		t.Errorf("after its digest: count = %d, want 1", got)
	}
}

// Digests that cannot be read hold the prefix with a digest_unreadable gap.
func TestDigest_UnreadableHoldsThePrefix(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	s := newDigestSigner(t)
	s.install(e)
	k, b := putLog(t, e, 1)
	d := s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}})
	e.bucket.status[d.key] = 403
	st := e.mustRun(t)
	if ct := st.CloudTrail; ct.Objects != 0 {
		t.Fatalf("stats = %+v", ct)
	}
	g := digestGap(e, t, "digest:"+dAcct+"/us-east-1", "digest_unreadable")
	if !strings.Contains(g.Detail, "ListPublicKeys") {
		t.Errorf("detail = %q", g.Detail)
	}
	if len(e.rows(t)) != 0 {
		t.Errorf("rows = %v", e.rows(t))
	}
	// access restored: the file is counted and the gap cleared
	delete(e.bucket.status, d.key)
	e.mustRun(t)
	if got := e.rows(t)[roleDE+dRows]; got != 1 {
		t.Errorf("count = %d", got)
	}
	if g := e.gaps(t)["cloudtrail digest:"+dAcct+"/us-east-1"]; g != nil {
		t.Errorf("the unreadable gap was not cleared: %+v", g)
	}
}

func TestDigest_PublicKeyNotFound(t *testing.T) {
	e := newUsageEnv(t, trailOnly())
	s := newDigestSigner(t)
	s.fp = "aaaa"
	s.install(e)
	s.fp = "bbbb" // the digest names a key AWS does not list
	k, b := putLog(t, e, 1)
	s.add(e, dAcct, "us-east-1", dEnd(3), digestOpt{listed: map[string]string{k: b}})
	st := e.mustRun(t)
	if ct := st.CloudTrail; ct.Objects != 0 || ct.Refused != 1 {
		t.Fatalf("stats = %+v", ct)
	}
	digestGap(e, t, k, "digest_invalid")
}

func TestReaderActionsHaveListPublicKeys(t *testing.T) {
	var found bool
	for _, a := range ReaderActions {
		found = found || a == "cloudtrail:ListPublicKeys"
	}
	if !found {
		t.Error("cloudtrail:ListPublicKeys is not in ReaderActions")
	}
}
