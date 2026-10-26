package awsorg

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CloudTrail log file integrity validation (issue #680). With validation on,
// CloudTrail writes an hourly digest file under
//
//	<prefix>/AWSLogs/[<org id>/]<account>/CloudTrail-Digest/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz
//
// that lists the SHA-256 of every log file delivered in the hour and links to
// the previous digest (its name, hash and signature). AWS signs each digest
// with SHA256withRSA and puts the signature, hex encoded, in the object's
// x-amz-meta-signature; the public key is the regional one that
// cloudtrail:ListPublicKeys returns for digestPublicKeyFingerprint.
//
// The ingest counts a log file only when a verified digest lists it with the
// hash it has. What it cannot confirm is a gap whose code starts with "digest_"
// (the LP-2 confidence model treats that as low confidence):
//
//	digest_invalid     a signature, hash or chain link does not verify: the file is refused
//	digest_missing     no digest lists the file, or the chain skips a digest: the file is refused
//	digest_disabled    the region has no digests at all (validation is off for the trail):
//	                   the files are counted, as before, and the gap says they are unverified
//	digest_unreadable  the digests or the public key could not be read: the prefix waits
//
// A file newer than digestGrace is waited for (the cursor stays before it)
// rather than refused: its digest is not published yet.

const (
	digestGrace          = 3 * time.Hour
	maxDigestObjectBytes = 16 << 20
	maxDigestInflated    = 64 << 20
	maxDigestsPerDay     = 100
	maxDigestLogFiles    = 200000
	maxPublicKeyBytes    = 1 << 20
	digestSigMetaHeader  = "X-Amz-Meta-Signature"
)

// digestKeyTailRE is a digest key relative to its region: yyyy/mm/dd/<file>.json.gz.
var digestKeyTailRE = regexp.MustCompile(`^[0-9]{4}/[0-9]{2}/[0-9]{2}/[A-Za-z0-9_.-]{1,250}\.json\.gz$`)

// logStampRE finds the time in a log file name (..._<yyyymmddThhmmZ>_<hash>.json.gz).
var logStampRE = regexp.MustCompile(`_([0-9]{8}T[0-9]{4}Z)_[A-Za-z0-9]+\.json\.gz$`)

// errDigestPending says a log file's digest is not published yet.
var errDigestPending = errors.New("awsorg: the digest of the log file is not published yet")

// digestError is a failure to read digests or the public key (not a verdict on them).
type digestError struct{ err error }

func (e *digestError) Error() string { return "reading CloudTrail digests: " + e.err.Error() }
func (e *digestError) Unwrap() error { return e.err }

type digestFile struct {
	DigestEndTime              string  `json:"digestEndTime"`
	DigestS3Bucket             string  `json:"digestS3Bucket"`
	DigestS3Object             string  `json:"digestS3Object"`
	DigestPublicKeyFingerprint string  `json:"digestPublicKeyFingerprint"`
	DigestSignatureAlgorithm   string  `json:"digestSignatureAlgorithm"`
	PreviousDigestS3Object     *string `json:"previousDigestS3Object"`
	PreviousDigestHashValue    *string `json:"previousDigestHashValue"`
	PreviousDigestSignature    *string `json:"previousDigestSignature"`
	LogFiles                   []struct {
		S3Bucket      string `json:"s3Bucket"`
		S3Object      string `json:"s3Object"`
		HashValue     string `json:"hashValue"`
		HashAlgorithm string `json:"hashAlgorithm"`
	} `json:"logFiles"`
}

// verifiedDigest is a digest whose signature checked out.
type verifiedDigest struct {
	f    digestFile
	end  time.Time
	hash string // SHA-256 of the digest file, hex
	sig  string // its signature, hex
}

// digestDay is what one day of a prefix's digests says.
type digestDay struct {
	files   map[string]string // log file key -> hash, from verified digests
	invalid string            // why a digest of the day cannot be trusted ("" when none)
	missing string            // why a digest of the day is gone ("" when none)
	count   int
}

type publicKeys map[string]*rsa.PublicKey // by lowercase fingerprint

// digestVerifier checks log files against the digests of one run. It is not
// safe for concurrent use.
type digestVerifier struct {
	t     *CloudTrailConfig
	sess  func() (session, error)
	now   time.Time
	floor time.Time

	days   map[string]*digestDay // "<account>/<region>/<yyyy/mm/dd>"
	exists map[string]bool       // "<account>/<region>": the region has digests
	keys   map[string]publicKeys // by region
}

func newDigestVerifier(t *CloudTrailConfig, sess func() (session, error), now, floor time.Time) *digestVerifier {
	return &digestVerifier{t: t, sess: sess, now: now, floor: floor,
		days: map[string]*digestDay{}, exists: map[string]bool{}, keys: map[string]publicKeys{}}
}

func (v *digestVerifier) dir(p *trailPrefix) string {
	return v.t.logRoot() + p.account + "/CloudTrail-Digest/" + p.region + "/"
}

// verdict is the outcome for one log file.
type verdict struct {
	Code   string // "" when verified; digest_invalid, digest_missing or digest_disabled
	Detail string
}

// check decides whether the log file at tail (relative to the prefix, with the
// SHA-256 of its inflated content) is confirmed. It returns errDigestPending
// for a file whose digest is not out yet and a *digestError for a read failure.
func (v *digestVerifier) check(ctx context.Context, p *trailPrefix, tail, hash string) (verdict, error) {
	key := p.dir + tail
	day := tail[:10]
	next := day
	if d, err := time.Parse("2006/01/02", day); err == nil {
		next = d.AddDate(0, 0, 1).Format("2006/01/02")
	}
	var dds []*digestDay
	for _, d := range []string{day, next} {
		dd, err := v.loadDay(ctx, p, d)
		if err != nil {
			return verdict{}, err
		}
		dds = append(dds, dd)
	}
	// a day with a digest that fails taints every file of it: a broken chain says nothing of which links still hold
	for _, dd := range dds {
		if dd.invalid != "" {
			return verdict{"digest_invalid", dd.invalid}, nil
		}
	}
	for _, dd := range dds {
		if dd.missing != "" {
			return verdict{"digest_missing", dd.missing}, nil
		}
	}
	for _, dd := range dds {
		if want, ok := dd.files[key]; ok {
			if want != hash {
				return verdict{"digest_invalid", "the log file's SHA-256 is not the one its digest lists"}, nil
			}
			return verdict{}, nil
		}
	}
	any, err := v.regionHasDigests(ctx, p)
	if err != nil {
		return verdict{}, err
	}
	if !any {
		return verdict{"digest_disabled", "the trail publishes no digest files for this region (log file validation is off), so its logs are unverified"}, nil
	}
	if at, ok := logFileTime(tail); !ok || v.now.Sub(at) < digestGrace {
		return verdict{}, errDigestPending
	}
	return verdict{"digest_missing", "no verified digest lists this log file"}, nil
}

func logFileTime(tail string) (time.Time, bool) {
	m := logStampRE.FindStringSubmatch(tail)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("20060102T1504Z", m[1])
	return t, err == nil
}

// regionHasDigests says whether any digest object exists for the prefix's region.
func (v *digestVerifier) regionHasDigests(ctx context.Context, p *trailPrefix) (bool, error) {
	if any, ok := v.exists[p.key]; ok {
		return any, nil
	}
	s, err := v.sess()
	if err != nil {
		return false, &digestError{err}
	}
	objs, _, _, err := s.listObjects(ctx, v.t, v.dir(p), "", "", "", 1)
	if err != nil {
		return false, &digestError{err}
	}
	v.exists[p.key] = len(objs) > 0
	return len(objs) > 0, nil
}

// loadDay lists, reads and verifies the digests of one day (yyyy/mm/dd).
func (v *digestVerifier) loadDay(ctx context.Context, p *trailPrefix, day string) (*digestDay, error) {
	ck := p.key + "/" + day
	if d := v.days[ck]; d != nil {
		return d, nil
	}
	s, err := v.sess()
	if err != nil {
		return nil, &digestError{err}
	}
	dir := v.dir(p)
	var objs []s3Obj
	tok := ""
	for pages := 0; pages < 3; pages++ {
		page, _, next, err := s.listObjects(ctx, v.t, dir+day+"/", "", "", tok, 1000)
		if err != nil {
			return nil, &digestError{err}
		}
		objs = append(objs, page...)
		if tok = next; tok == "" {
			break
		}
	}
	dd := &digestDay{files: map[string]string{}}
	var ds []*verifiedDigest
	for _, o := range objs {
		tail := strings.TrimPrefix(o.Key, dir)
		if !digestKeyTailRE.MatchString(tail) {
			continue
		}
		if dd.count++; dd.count > maxDigestsPerDay {
			dd.invalid = fmt.Sprintf("more than %d digest files for one day", maxDigestsPerDay)
			break
		}
		if o.Size > maxDigestObjectBytes {
			dd.invalid = "a digest file is over the size limit: " + clip(tail, 120)
			continue
		}
		vd, msg, err := v.readDigest(ctx, s, p, o.Key)
		if err != nil {
			return nil, err // not cached: the read may pass
		}
		if msg != "" {
			if dd.invalid == "" {
				dd.invalid = msg
			}
			continue
		}
		ds = append(ds, vd)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].end.Before(ds[j].end) })
	dd.chain(ds)
	if dd.missing == "" && dd.invalid == "" && len(ds) > 0 {
		if err := v.checkBefore(ctx, s, p, ds[0], dd); err != nil {
			return nil, err
		}
	}
	for _, d := range ds {
		for _, lf := range d.f.LogFiles {
			dd.files[lf.S3Object] = strings.ToLower(lf.HashValue)
		}
	}
	v.days[ck] = dd
	return dd, nil
}

// chain checks that each digest links to the one before it in the same day.
func (dd *digestDay) chain(ds []*verifiedDigest) {
	for i := 1; i < len(ds); i++ {
		prev, d := ds[i-1], ds[i]
		switch {
		case d.f.PreviousDigestS3Object == nil || *d.f.PreviousDigestS3Object != prev.f.DigestS3Object:
			if dd.missing == "" {
				dd.missing = "the digest chain skips a digest before " + clip(d.f.DigestS3Object, 200)
			}
		case d.f.PreviousDigestHashValue == nil || !strings.EqualFold(*d.f.PreviousDigestHashValue, prev.hash),
			d.f.PreviousDigestSignature == nil || !strings.EqualFold(*d.f.PreviousDigestSignature, prev.sig):
			if dd.invalid == "" {
				dd.invalid = "a digest does not match the hash or signature its successor records: " + clip(prev.f.DigestS3Object, 200)
			}
		}
	}
}

// checkBefore confirms the digest that the day's first digest links to exists,
// when it lies after the backfill floor (older ones may have expired).
func (v *digestVerifier) checkBefore(ctx context.Context, s session, p *trailPrefix, first *verifiedDigest, dd *digestDay) error {
	if first.f.PreviousDigestS3Object == nil {
		return nil // the first digest of the trail
	}
	prev := *first.f.PreviousDigestS3Object
	dir := v.dir(p)
	tail := strings.TrimPrefix(prev, dir)
	if !strings.HasPrefix(prev, dir) || !digestKeyTailRE.MatchString(tail) {
		dd.invalid = "a digest links to a previous digest outside the trail's digest prefix"
		return nil
	}
	if d, err := time.Parse("2006/01/02", tail[:10]); err != nil || d.Before(v.floor.AddDate(0, 0, -1)) {
		return nil
	}
	objs, _, _, err := s.listObjects(ctx, v.t, prev, "", "", "", 1)
	if err != nil {
		return &digestError{err}
	}
	if len(objs) == 0 || objs[0].Key != prev {
		dd.missing = "the previous digest is missing: " + clip(prev, 200)
	}
	return nil
}

// readDigest fetches one digest and verifies its signature. msg is non-empty
// when the digest cannot be trusted; err when it could not be read.
func (v *digestVerifier) readDigest(ctx context.Context, s session, p *trailPrefix, key string) (*verifiedDigest, string, error) {
	gzb, hdr, err := s.getObject(ctx, v.t, key, maxDigestObjectBytes)
	if err != nil {
		return nil, "", &digestError{err}
	}
	raw, err := inflateAll(gzb, maxDigestInflated)
	if err != nil {
		return nil, "a digest file is not valid gzip or is too large: " + clip(key, 200), nil
	}
	var f digestFile
	if err := json.Unmarshal(raw, &f); err != nil || len(f.LogFiles) > maxDigestLogFiles {
		return nil, "a digest file is not valid JSON: " + clip(key, 200), nil
	}
	if f.DigestS3Bucket != v.t.Bucket || f.DigestS3Object != key {
		return nil, "a digest names another location than the one it was read from: " + clip(key, 200), nil
	}
	end, err := time.Parse(time.RFC3339, f.DigestEndTime)
	if err != nil {
		return nil, "a digest has no valid end time: " + clip(key, 200), nil
	}
	if f.DigestSignatureAlgorithm != "SHA256withRSA" {
		return nil, "a digest uses an unsupported signature algorithm: " + clip(key, 200), nil
	}
	sig, err := hex.DecodeString(hdr.Get(digestSigMetaHeader))
	if err != nil || len(sig) == 0 {
		return nil, "a digest has no signature in its object metadata: " + clip(key, 200), nil
	}
	pub, msg, err := v.publicKey(ctx, s, p.region, f.DigestPublicKeyFingerprint, end)
	if err != nil || msg != "" {
		return nil, msg, err
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	prevSig := "null"
	if f.PreviousDigestSignature != nil {
		prevSig = *f.PreviousDigestSignature
	}
	signed := f.DigestEndTime + "\n" + f.DigestS3Bucket + "/" + f.DigestS3Object + "\n" + hash + "\n" + prevSig
	h := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return nil, "a digest's signature does not verify: " + clip(key, 200), nil
	}
	for _, lf := range f.LogFiles {
		if lf.S3Bucket != v.t.Bucket || !strings.EqualFold(lf.HashAlgorithm, "SHA-256") {
			return nil, "a digest lists a log file of another bucket or with another hash algorithm: " + clip(key, 200), nil
		}
	}
	return &verifiedDigest{f: f, end: end.UTC(), hash: hash, sig: hex.EncodeToString(sig)}, "", nil
}

type listKeysResponse struct {
	PublicKeyList []struct {
		Value       string `json:"Value"` // base64 PKIX DER
		Fingerprint string `json:"Fingerprint"`
	} `json:"PublicKeyList"`
}

// publicKey is the regional key with the fingerprint (cloudtrail ListPublicKeys).
func (v *digestVerifier) publicKey(ctx context.Context, s session, region, fingerprint string, at time.Time) (*rsa.PublicKey, string, error) {
	fp := strings.ToLower(fingerprint)
	if fp == "" {
		return nil, "a digest names no public key", nil
	}
	if k := v.keys[region][fp]; k != nil {
		return k, "", nil
	}
	var r listKeysResponse
	in := map[string]float64{"StartTime": float64(at.Add(-24 * time.Hour).Unix()), "EndTime": float64(at.Add(time.Hour).Unix())}
	if err := s.jsonCall(ctx, svcCloudTrail, region, cloudTrailTarget+"ListPublicKeys", json11, in, &r); err != nil {
		return nil, "", &digestError{err}
	}
	if v.keys[region] == nil {
		v.keys[region] = publicKeys{}
	}
	for _, e := range r.PublicKeyList {
		der, err := base64.StdEncoding.DecodeString(e.Value)
		if err != nil || len(der) > maxPublicKeyBytes {
			continue
		}
		pk, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			continue
		}
		if rk, ok := pk.(*rsa.PublicKey); ok {
			v.keys[region][strings.ToLower(e.Fingerprint)] = rk
		}
	}
	if k := v.keys[region][fp]; k != nil {
		return k, "", nil
	}
	return nil, "no CloudTrail public key has the fingerprint a digest names: " + clip(fp, 80), nil
}

// getObject reads an object with a size bound and returns its response headers.
func (s session) getObject(ctx context.Context, t *CloudTrailConfig, key string, max int) ([]byte, http.Header, error) {
	host, base, err := bucketRequest(t.Bucket, t.Region)
	if err != nil {
		return nil, nil, err
	}
	path := "/" + key
	if base != "/" {
		path = base + "/" + key
	}
	return s.cl.do(ctx, s.creds, call{Service: svcS3, Host: host, Region: t.Region, Method: http.MethodGet, Path: path,
		Header: ownerHeader(t.AccountID), Op: "GetObject", MaxBytes: max})
}

// inflateAll inflates gz, failing past limit bytes.
func inflateAll(gz []byte, limit int) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	b, err := io.ReadAll(io.LimitReader(zr, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("inflates past the limit")
	}
	return b, nil
}

// inflatedSHA256 is the hex SHA-256 of the inflated log file, the hash digests list.
func inflatedSHA256(gz []byte) (string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", &refusal{"malformed", "not a gzip file"}
	}
	defer zr.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(zr, int64(maxLogInflatedBytes)+1))
	if err != nil {
		return "", &refusal{"malformed", "not a gzip file"}
	}
	if n > int64(maxLogInflatedBytes) {
		return "", &refusal{"inflated_too_large", fmt.Sprintf("the log file inflates to more than %d bytes", maxLogInflatedBytes)}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
