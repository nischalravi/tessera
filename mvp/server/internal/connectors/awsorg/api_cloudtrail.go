package awsorg

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// CloudTrail logs in S3 (issue #644). Read actions only: s3:ListBucket
// (ListObjectsV2), s3:GetObject, and cloudtrail:GetEventSelectors.
//
// A trail writes gzip files of {"Records": [...]} under
//
//	<prefix>/AWSLogs/[<org id>/]<account>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz
//
// The bucket, its keys and every byte in a file are the customer's data, so
// nothing is trusted: the key grammar, the object size, the inflated size and
// the record count are bounded before anything is kept, and a file that
// breaks a bound is refused whole (a refusal is a gap, never a partial count).

// Per-file bounds. They are variables of the package only so tests can lower them.
var (
	maxLogObjectBytes   = 16 << 20  // compressed size of one log file
	maxLogInflatedBytes = 128 << 20 // what one file may inflate to
	maxLogRecords       = 200000    // records in one file
	maxLogRecordBytes   = 4 << 20   // one record (CloudTrail's own cap is far lower): encoding/json buffers a whole one
)

const (
	maxListResponseBytes = 8 << 20
	listPageKeys         = 100
	maxRegionPrefixes    = 40
)

// logKeyRE is a log file key relative to the prefix of its account and region:
// yyyy/mm/dd/<file>.json.gz. The file name is the one CloudTrail writes
// (account_CloudTrail_region_timestamp_hash.json.gz), loosely checked.
var logKeyTailRE = regexp.MustCompile(`^[0-9]{4}/[0-9]{2}/[0-9]{2}/[A-Za-z0-9_.-]{1,200}\.json\.gz$`)

// refusal is a log file or object the ingest will not read; Code is the gap
// code recorded for it.
type refusal struct{ Code, Msg string }

func (r *refusal) Error() string { return r.Code + ": " + r.Msg }

// s3Obj is one entry of a bucket listing.
type s3Obj struct {
	Key  string
	Size int64
}

type s3ListObjects struct {
	Truncated bool `xml:"IsTruncated"`
	Contents  []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	Prefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
	Next string `xml:"NextContinuationToken"`
}

func ownerHeader(account string) http.Header {
	return http.Header{"X-Amz-Expected-Bucket-Owner": {account}}
}

// listObjects is one ListObjectsV2 page of prefix, after startAfter (exclusive).
// With a delimiter, the sub-prefixes are returned instead of the keys under them.
func (s session) listObjects(ctx context.Context, t *CloudTrailConfig, prefix, startAfter, delimiter, token string, max int) (objs []s3Obj, prefixes []string, next string, err error) {
	host, path, err := bucketRequest(t.Bucket, t.Region)
	if err != nil {
		return nil, nil, "", err
	}
	q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {fmt.Sprint(max)}}
	if startAfter != "" {
		q.Set("start-after", startAfter)
	}
	if delimiter != "" {
		q.Set("delimiter", delimiter)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	body, _, err := s.cl.do(ctx, s.creds, call{Service: svcS3, Host: host, Region: t.Region, Method: http.MethodGet, Path: path, Query: q,
		Header: ownerHeader(t.AccountID), Op: "ListObjectsV2", MaxBytes: maxListResponseBytes})
	if err != nil {
		return nil, nil, "", err
	}
	var r s3ListObjects
	if err := decodeXML(body, &r, svcS3, "ListObjectsV2"); err != nil {
		return nil, nil, "", err
	}
	for _, c := range r.Contents {
		objs = append(objs, s3Obj{Key: c.Key, Size: c.Size})
	}
	for _, p := range r.Prefixes {
		prefixes = append(prefixes, p.Prefix)
	}
	if r.Truncated {
		if r.Next == "" {
			return nil, nil, "", errors.New("aws: s3 ListObjectsV2: truncated page with no continuation token")
		}
		next = r.Next
	}
	return objs, prefixes, next, nil
}

// getLogObject reads one log file, refusing one larger than maxLogObjectBytes.
func (s session) getLogObject(ctx context.Context, t *CloudTrailConfig, key string) ([]byte, error) {
	host, base, err := bucketRequest(t.Bucket, t.Region)
	if err != nil {
		return nil, err
	}
	path := "/" + key
	if base != "/" {
		path = base + "/" + key
	}
	body, _, err := s.cl.do(ctx, s.creds, call{Service: svcS3, Host: host, Region: t.Region, Method: http.MethodGet, Path: path,
		Header: ownerHeader(t.AccountID), Op: "GetObject", MaxBytes: maxLogObjectBytes})
	return body, err
}

// ---------------------------------------------------------------- log files

// ctEvent is the part of a CloudTrail record the ingest reads.
type ctEvent struct {
	EventTime     string     `json:"eventTime"`
	EventSource   string     `json:"eventSource"`
	EventName     string     `json:"eventName"`
	EventType     string     `json:"eventType"`
	EventCategory string     `json:"eventCategory"`
	ErrorCode     string     `json:"errorCode"`
	UserIdentity  ctIdentity `json:"userIdentity"`
	Resources     []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

// inflateLimit reads at most n bytes and then fails, so a small file cannot
// inflate to an unbounded size.
type inflateLimit struct {
	r     io.Reader
	n     int
	total int64 // bytes read so far
	// recFrom is the stream offset where the record being decoded starts, -1
	// outside the Records array. Reading on past recFrom+maxLogRecordBytes means
	// the record is too big to buffer.
	recFrom int64
}

func (l *inflateLimit) Read(p []byte) (int, error) {
	if l.recFrom >= 0 && l.total-l.recFrom > int64(maxLogRecordBytes) {
		return 0, &refusal{"record_too_large", fmt.Sprintf("a record in the log file is larger than %d bytes", maxLogRecordBytes)}
	}
	if l.n <= 0 {
		// a file of exactly the limit is accepted: only a byte past it refuses
		var one [1]byte
		for i := 0; i < 100; i++ {
			k, err := l.r.Read(one[:])
			if k > 0 {
				break
			}
			if err != nil {
				return 0, err
			}
		}
		return 0, &refusal{"inflated_too_large", fmt.Sprintf("the log file inflates to more than %d bytes", maxLogInflatedBytes)}
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	l.total += int64(n)
	return n, err
}

// parseLogFile decodes one gzip log file and calls fn for each record, in
// order. It streams, so memory is bounded by one record. It returns a
// *refusal for a file that is not a CloudTrail log, is larger than its
// bounds, or is cut off; fn may have been called for some records by then, so
// the caller keeps nothing of a refused file.
func parseLogFile(gz []byte, fn func(*ctEvent)) (records int, err error) {
	if len(gz) > maxLogObjectBytes {
		return 0, &refusal{"too_large", fmt.Sprintf("the log file is %d bytes, over the limit of %d", len(gz), maxLogObjectBytes)}
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return 0, &refusal{"malformed", "not a gzip file"}
	}
	defer zr.Close()
	lim := &inflateLimit{r: zr, n: maxLogInflatedBytes, recFrom: -1}
	dec := json.NewDecoder(lim)
	bad := func(msg string) error { return &refusal{"malformed", msg} }
	wrap := func(err error) error {
		var rf *refusal
		if errors.As(err, &rf) {
			return rf
		}
		return bad("not a CloudTrail log file")
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, wrap(err)
	}
	seen := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return records, wrap(err)
		}
		key, _ := kt.(string)
		if key != "Records" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return records, wrap(err)
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return records, wrap(err)
		}
		seen = true
		for dec.More() {
			if records >= maxLogRecords {
				return records, &refusal{"too_many_records", fmt.Sprintf("the log file has more than %d records", maxLogRecords)}
			}
			var ev ctEvent
			lim.recFrom = dec.InputOffset()
			err := dec.Decode(&ev)
			lim.recFrom = -1
			if err != nil {
				return records, wrap(err)
			}
			records++
			fn(&ev)
		}
		if t, err := dec.Token(); err != nil || t != json.Delim(']') {
			return records, wrap(err)
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return records, wrap(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return records, bad("data after the end of the log")
	}
	if !seen {
		return 0, bad("no Records")
	}
	return records, nil
}

func parseEventTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, s)
	return t.UTC(), err == nil
}

// ---------------------------------------------------------------- event selectors

const svcCloudTrail = "cloudtrail"

const cloudTrailTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."

type ctSelectors struct {
	EventSelectors []struct {
		ReadWriteType           string `json:"ReadWriteType"`
		IncludeManagementEvents bool   `json:"IncludeManagementEvents"`
		DataResources           []struct {
			Type   string   `json:"Type"`
			Values []string `json:"Values"`
		} `json:"DataResources"`
	} `json:"EventSelectors"`
	AdvancedEventSelectors []struct {
		FieldSelectors []struct {
			Field      string   `json:"Field"`
			Equals     []string `json:"Equals"`
			StartsWith []string `json:"StartsWith"`
			NotEquals  []string `json:"NotEquals"`
		} `json:"FieldSelectors"`
	} `json:"AdvancedEventSelectors"`
}

// getEventSelectors reads the trail's event selectors (cloudtrail
// GetEventSelectors, in the trail's home region).
func (s session) getEventSelectors(ctx context.Context, region, trailARN string) (*ctSelectors, error) {
	var r ctSelectors
	err := s.jsonCall(ctx, svcCloudTrail, region, cloudTrailTarget+"GetEventSelectors", json11, map[string]string{"TrailName": trailARN}, &r)
	return &r, err
}

// s3DataEvents says whether the selectors log every S3 object-level call (the
// data events): "enabled" only when a selector covers all buckets and both
// reads and writes; "disabled" when none touches S3 objects; "unknown" when
// they cover only some (advanced selectors can be narrowed by bucket, by
// read/write or by name), because a call outside the covered part is not in the
// logs and "not seen" would then not mean "not used".
func (r *ctSelectors) s3DataEvents() (state, detail string) {
	any, full := false, false
	for _, es := range r.EventSelectors {
		for _, d := range es.DataResources {
			if d.Type != "AWS::S3::Object" || len(d.Values) == 0 {
				continue
			}
			any = true
			if es.ReadWriteType == "All" && containsFold(d.Values, "arn:aws:s3") {
				full = true
			}
		}
	}
	for _, as := range r.AdvancedEventSelectors {
		data, s3, narrowed := false, true, false
		for _, f := range as.FieldSelectors {
			switch f.Field {
			case "eventCategory":
				data = containsFold(f.Equals, "Data")
			case "resources.type":
				s3 = containsFold(f.Equals, "AWS::S3::Object")
			case "resources.ARN":
				if !containsFold(f.StartsWith, "arn:aws:s3") && !containsFold(f.StartsWith, "arn:aws:s3:::") {
					narrowed = true
				}
			case "readOnly", "eventName", "userIdentity.arn", "eventSource":
				narrowed = true
			}
		}
		if data && s3 {
			any = true
			if !narrowed {
				full = true
			}
		}
	}
	switch {
	case full:
		return "enabled", ""
	case any:
		return "unknown", "S3 data events are logged for only some buckets, or only reads or writes"
	}
	return "disabled", "the trail does not log S3 data events"
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
