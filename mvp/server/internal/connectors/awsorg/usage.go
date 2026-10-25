package awsorg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Usage ingest (issue #644, LP-1; docs/design/differentiators-plan.md section 3):
// what each principal did, from the organization's CloudTrail (S3) and from IAM
// Access Advisor, filed per principal, action, resource scope and day in
// aws_usage_daily, in the evaluator's action names.
//
// It reads like the estate collector (assumed reader roles, the signed client,
// read actions only) and runs next to it: CollectAndMaterialize calls
// CollectUsage for a connector whose config has "usage". A failure here never
// fails the estate collection. What cannot be read is recorded as a gap
// (aws_usage_gaps), so a missing row is never taken for "unused"; how much a
// gap weighs is the confidence model's business (LP-2).
//
// Exactly-once: a batch of usage rows and the cursor that says which log files
// they came from are written in one transaction, so a crash re-reads a file
// that was not counted and never counts one twice. The cursor is per account
// and region, the last key read, relying on the S3 listing order (key order):
// a file delivered later with a key before the cursor is not read. CloudTrail
// names files by their time window, so this only loses a file delivered more
// than a window late; the window of days covered (covered_to) is the day the
// slowest prefix has reached, not "now".

const (
	// usageRetention is how long usage rows are kept (Access Advisor looks back 400 days).
	usageRetention = 400 * 24 * time.Hour
	gapRetention   = 180 * 24 * time.Hour
	maxPrefixes    = 2000
	maxUnmapped    = 20
	// advisorEvery is how long a finished Access Advisor round rests.
	advisorEvery = 24 * time.Hour
	// advisorPace is the wait between principals, under IAM's request rate.
	advisorPace = 500 * time.Millisecond
	// advisorMaxNotReady consecutive reports that do not finish end the run.
	advisorMaxNotReady = 3
	dayLayout          = "2006-01-02"
)

// Run bounds. They are variables of the package only so tests can lower them.
var (
	// maxUsageRows bounds the distinct rows one CloudTrail run holds: past it,
	// new rows are filed at scope "*", and the run stops after the file that
	// reached it (the rest is read by the next run).
	maxUsageRows = 200000
	// advisorRunBudget bounds one run's Access Advisor time. A report can take a
	// minute of polling and a throttled call the client's backoff, so 1000
	// principals could hold the worker for hours, past awsRunStaleAfter (when the
	// run is failed as stale and another may start). The rest wait for a later run.
	advisorRunBudget = 30 * time.Minute
)

// UsageCollector reads usage for one connector.
type UsageCollector struct {
	Client     *Client
	Config     *Config
	Base       sigv4.Credentials
	ExternalID string
	Now        func() time.Time
	Mapper     ActionMapper
}

func (u *UsageCollector) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *UsageCollector) collector() (*Collector, map[string]*accountSession) {
	return &Collector{Client: u.Client, Config: u.Config, Base: u.Base, ExternalID: u.ExternalID, Now: u.Now}, map[string]*accountSession{}
}

// TrailStats summarizes one CloudTrail run (counts only).
type TrailStats struct {
	Objects      int    `json:"objects"`  // log files read
	Refused      int    `json:"refused"`  // log files refused (too large, malformed): gaps
	Records      int    `json:"records"`  // records in the files read
	Counted      int    `json:"counted"`  // API calls filed as usage
	Failed       int    `json:"failed"`   // calls that errored (denied calls are not usage)
	Skipped      int    `json:"skipped"`  // not an API call, or no user or role behind it
	Unmapped     int    `json:"unmapped"` // calls whose action the catalog does not have
	Rows         int    `json:"rows"`
	Gaps         int    `json:"gaps"`
	Backlog      bool   `json:"backlog,omitempty"` // the run stopped at its object limit with files left
	S3DataEvents string `json:"s3_data_events"`
	CoveredFrom  string `json:"covered_from,omitempty"`
	CoveredTo    string `json:"covered_to,omitempty"`
}

// AdvisorStats summarizes one Access Advisor run.
type AdvisorStats struct {
	Principals int  `json:"principals"` // read this run
	Remaining  int  `json:"remaining"`  // left for later runs of this round
	Rows       int  `json:"rows"`
	Gaps       int  `json:"gaps"`
	Resting    bool `json:"resting,omitempty"` // the last round finished less than a day ago: nothing was called
}

// UsageStats is what one CollectUsage did.
type UsageStats struct {
	CloudTrail *TrailStats   `json:"cloudtrail,omitempty"`
	Advisor    *AdvisorStats `json:"access_advisor,omitempty"`
}

// usageBatch is what one source's run produced, to be written in one transaction.
type usageBatch struct {
	rows  []*store.AWSUsageDay
	set   bool // rows replace (Access Advisor) instead of adding
	gaps  []store.AWSUsageGap
	clear []string // gap refs that no longer apply
	state store.AWSUsageState
}

// ---------------------------------------------------------------- CloudTrail

type trailCursor struct {
	// Prefixes maps "<account>/<region>" to the last key read there, relative
	// to that prefix (yyyy/mm/dd/<file>).
	Prefixes map[string]string `json:"prefixes"`
}

type usageKey struct{ principal, action, scope, day string }

type usageVal struct {
	count int64
	last  time.Time
}

type trailPrefix struct {
	account, region, dir, key string
	after                     string // the S3 key after which to list
	last                      string // the last tail read (cursor value), "" if none
	drained, blocked          bool
}

// collectTrail reads new log files of the trail for accounts, from prior. The
// batch is always usable: a run that fails early returns the prior cursor and
// the gaps that explain it, with the error.
func (u *UsageCollector) collectTrail(ctx context.Context, connectorID string, accounts []string, prior *store.AWSUsageState) (*usageBatch, *TrailStats, error) {
	t := u.Config.Usage.CloudTrail
	now := u.now()
	cur := trailCursor{Prefixes: map[string]string{}}
	if prior != nil && len(prior.Cursor) > 0 {
		if err := json.Unmarshal(prior.Cursor, &cur); err != nil || cur.Prefixes == nil {
			cur = trailCursor{Prefixes: map[string]string{}} // an unreadable cursor starts over: the backfill window bounds the re-read
		}
	}
	st := &TrailStats{S3DataEvents: store.AWSDataEventsUnknown}
	b := &usageBatch{state: store.AWSUsageState{ConnectorID: connectorID, Source: store.AWSUsageCloudTrail, S3DataEvents: store.AWSDataEventsUnknown, UpdatedAt: now}}
	if prior != nil {
		b.state.CoveredFrom, b.state.CoveredTo, b.state.S3DataEvents = prior.CoveredFrom, prior.CoveredTo, prior.S3DataEvents
		st.S3DataEvents = prior.S3DataEvents
	}
	floor := now.UTC().AddDate(0, 0, -t.BackfillDays)
	if b.state.CoveredFrom == "" {
		b.state.CoveredFrom = floor.Format(dayLayout)
	}
	gap := func(source, ref, code, detail, day string) {
		b.gaps = append(b.gaps, store.AWSUsageGap{ConnectorID: connectorID, Source: source, Ref: ref, Code: code, Detail: clip(detail, 400), Day: day, RecordedAt: now})
	}
	finish := func(err error) (*usageBatch, *TrailStats, error) {
		raw, merr := json.Marshal(cur)
		if merr != nil {
			return b, st, errors.Join(err, merr)
		}
		b.state.Cursor = raw
		st.Rows, st.Gaps = len(b.rows), len(b.gaps)
		st.CoveredFrom, st.CoveredTo = b.state.CoveredFrom, b.state.CoveredTo
		st.S3DataEvents = b.state.S3DataEvents
		return b, st, err
	}

	col, cache := u.collector()
	// whether S3 data events are logged: best effort, and never a reason to stop
	b.state.S3DataEvents = u.dataEvents(ctx, col, cache, t, gapRecorder(gap), &b.clear)

	if len(accounts) == 0 {
		gap(store.AWSUsageCloudTrail, "trail", "no_accounts", "the connector has no collected snapshot yet, so there are no accounts to read logs for", "")
		return finish(nil)
	}
	sess := func() (session, error) {
		s, err := col.assume(ctx, cache, t.AccountID)
		if err != nil {
			return session{}, err
		}
		return s.session, nil
	}
	root := t.logRoot()
	var tracked []*trailPrefix
	fails, listFailed := 0, 0
	for _, acct := range accounts {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		s, err := sess()
		if err != nil {
			gap(store.AWSUsageCloudTrail, "trail", "assume_failed", "cannot assume the reader role in the bucket's account: "+errDetail(err), "")
			return finish(fmt.Errorf("awsorg: usage: assume the role in the trail bucket's account: %w", err))
		}
		base := root + acct + "/CloudTrail/"
		var regions []string
		tok, listed := "", true
		for pages := 0; pages < 10; pages++ {
			_, prefixes, next, err := s.listObjects(ctx, t, base, "", "/", tok, 1000)
			if err != nil {
				if ctx.Err() != nil {
					return finish(ctx.Err())
				}
				fails++
				listed = false
				gap(store.AWSUsageCloudTrail, "list:"+acct, errCode(err), "listing the trail's log prefix: "+u.accessHint(err, t), "")
				break
			}
			fails = 0
			for _, p := range prefixes {
				if r := strings.TrimSuffix(strings.TrimPrefix(p, base), "/"); regionRE.MatchString(r) {
					regions = append(regions, r)
				}
			}
			if tok = next; tok == "" {
				break
			}
		}
		if fails >= 3 {
			return finish(errors.New("awsorg: usage: the trail's log prefix cannot be listed (3 accounts in a row failed)"))
		}
		if !listed {
			listFailed++
		} else {
			// only a listing that worked clears its gap: clearing it on a failure deleted the gap
			// recorded the run before, so an unreadable account looked covered every other run
			b.clear = append(b.clear, "list:"+acct)
		}
		slices.Sort(regions)
		regions = slices.Compact(regions)
		if len(regions) > maxRegionPrefixes {
			gap(store.AWSUsageCloudTrail, "regions:"+acct, "too_many_regions", fmt.Sprintf("more than %d regions in the log prefix", maxRegionPrefixes), "")
			regions = regions[:maxRegionPrefixes]
		}
		for _, r := range regions {
			if len(tracked) >= maxPrefixes {
				gap(store.AWSUsageCloudTrail, "prefixes", "too_many_prefixes", fmt.Sprintf("more than %d account and region prefixes", maxPrefixes), "")
				break
			}
			p := &trailPrefix{account: acct, region: r, dir: base + r + "/", key: acct + "/" + r}
			if tail, ok := cur.Prefixes[p.key]; ok && logKeyTailRE.MatchString(tail) {
				p.after, p.last = p.dir+tail, tail
			} else {
				p.after = p.dir + floor.Format("2006/01/02") + "/"
			}
			tracked = append(tracked, p)
		}
	}

	if listFailed == len(accounts) {
		return finish(errors.New("awsorg: usage: the trail's log prefix cannot be listed"))
	}
	agg := map[usageKey]*usageVal{}
	unmapped := map[string]bool{}
	// a record's time is the customer's data: one far in the future would be a row
	// that never ages out, and one older than the retention is pruned at once
	evFrom, evTo := now.Add(-usageRetention), now.Add(24*time.Hour)
	full := false // the run holds maxUsageRows keys: it stops after the file that reached them
	merge := func(local map[usageKey]*usageVal) {
		for k, v := range local {
			if g := agg[k]; g != nil {
				g.count += v.count
				if v.last.After(g.last) {
					g.last = v.last
				}
			} else {
				agg[k] = v
			}
		}
	}
	// readObject reads one log file into agg. advance is false when the file
	// could not be read for a reason that may pass (the cursor stays before it).
	readObject := func(p *trailPrefix, o s3Obj) (advance bool, err error) {
		tail := strings.TrimPrefix(o.Key, p.dir)
		if !strings.HasPrefix(o.Key, p.dir) || !logKeyTailRE.MatchString(tail) {
			return true, nil // not a log file (a digest or a stray object)
		}
		day := strings.ReplaceAll(tail[:10], "/", "-")
		refuse := func(code, detail string) {
			st.Refused++
			gap(store.AWSUsageCloudTrail, o.Key, code, detail, day)
		}
		if o.Size > int64(maxLogObjectBytes) {
			refuse("too_large", fmt.Sprintf("the log file is %d bytes, over the limit of %d", o.Size, maxLogObjectBytes))
			return true, nil
		}
		s, err := sess()
		if err != nil {
			return false, err
		}
		body, err := s.getLogObject(ctx, t, o.Key)
		if err != nil {
			if errors.Is(err, safehttp.ErrTooLarge) {
				refuse("too_large", "the log file is over the limit of "+fmt.Sprint(maxLogObjectBytes)+" bytes")
				return true, nil
			}
			return false, err
		}
		local := map[usageKey]*usageVal{}
		n, perr := parseLogFile(body, func(ev *ctEvent) {
			u.fileEvent(ev, local, len(agg)+len(local) >= maxUsageRows, evFrom, evTo, st, unmapped)
		})
		var rf *refusal
		if errors.As(perr, &rf) {
			refuse(rf.Code, rf.Msg)
			return true, nil
		}
		if perr != nil {
			return false, perr
		}
		st.Objects++
		st.Records += n
		merge(local)
		if len(agg) >= maxUsageRows {
			full = true
		}
		return true, nil
	}

	budget := t.MaxObjectsPerRun
	for budget > 0 {
		progressed := false
		active := 0
		for _, p := range tracked {
			if !p.drained && !p.blocked {
				active++
			}
		}
		if active == 0 {
			break
		}
		for _, p := range tracked {
			if p.drained || p.blocked {
				continue
			}
			if err := ctx.Err(); err != nil {
				return finish(err)
			}
			if budget <= 0 {
				break
			}
			s, err := sess()
			if err != nil {
				return finish(err)
			}
			// each prefix takes its share of what is left, so one busy prefix cannot use the whole run
			objs, _, next, err := s.listObjects(ctx, t, p.dir, p.after, "", "", min(listPageKeys, max(1, budget/active)))
			if err != nil {
				if ctx.Err() != nil {
					return finish(ctx.Err())
				}
				p.blocked = true
				gap(store.AWSUsageCloudTrail, "s3:"+p.key, errCode(err), "listing log files: "+u.accessHint(err, t), "")
				continue
			}
			consumed := true
			for _, o := range objs {
				if budget <= 0 || full {
					consumed = false
					break
				}
				if tail := strings.TrimPrefix(o.Key, p.dir); strings.HasPrefix(o.Key, p.dir) && logKeyTailRE.MatchString(tail) && !plausibleKeyDay(tail, now) {
					// keys sort by day, so the cursor would rest past every file delivered after it: stop
					// before it, and read up to it again next run
					p.blocked = true
					gap(store.AWSUsageCloudTrail, "s3:"+p.key, "implausible_key", "a log file key is dated in the future or is not a date: "+clip(tail, 220), "")
					break
				}
				budget--
				progressed = true
				advance, err := readObject(p, o)
				if err != nil {
					if ctx.Err() != nil {
						return finish(ctx.Err())
					}
					p.blocked = true
					gap(store.AWSUsageCloudTrail, "s3:"+p.key, errCode(err), "reading "+p.key+"/"+strings.TrimPrefix(o.Key, p.dir)+": "+u.accessHint(err, t), "")
					break
				}
				if advance {
					p.after = o.Key
					// the cursor only rests on a log file key: a stray object after it is passed over again next run
					if tail := strings.TrimPrefix(o.Key, p.dir); strings.HasPrefix(o.Key, p.dir) && logKeyTailRE.MatchString(tail) {
						p.last = tail
					}
				}
			}
			if !p.blocked && consumed && next == "" {
				p.drained = true
			}
		}
		if !progressed || full {
			break
		}
	}

	today := now.UTC().Format(dayLayout)
	through := ""
	for _, p := range tracked {
		if p.last != "" && logKeyTailRE.MatchString(p.last) {
			cur.Prefixes[p.key] = p.last
		}
		if !p.drained {
			st.Backlog = st.Backlog || !p.blocked
		} else if !p.blocked {
			b.clear = append(b.clear, "s3:"+p.key)
		}
		d := today
		if !p.drained {
			d = floor.AddDate(0, 0, -1).Format(dayLayout)
			if p.last != "" && logKeyTailRE.MatchString(p.last) {
				d = strings.ReplaceAll(p.last[:10], "/", "-")
			}
		}
		if through == "" || d < through {
			through = d
		}
	}
	if through != "" {
		b.state.CoveredTo = through
	}
	if len(unmapped) > 0 {
		names := make([]string, 0, len(unmapped))
		for n := range unmapped {
			names = append(names, n)
		}
		sort.Strings(names)
		gap(store.AWSUsageCloudTrail, "unmapped_actions", "unmapped_actions", "calls whose action is not in the action catalog: "+strings.Join(names, ", "), "")
	} // else the gap stays: it describes calls already counted as unmapped, and ages out with the gap retention
	keys := make([]usageKey, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		return a.principal+"\x00"+a.action+"\x00"+a.scope+"\x00"+a.day < c.principal+"\x00"+c.action+"\x00"+c.scope+"\x00"+c.day
	})
	for _, k := range keys {
		v := agg[k]
		b.rows = append(b.rows, &store.AWSUsageDay{ConnectorID: connectorID, PrincipalARN: k.principal, Action: k.action, ResourceScope: k.scope,
			Day: k.day, Source: store.AWSUsageCloudTrail, Count: v.count, LastSeen: v.last})
	}
	return finish(nil)
}

// fileEvent files one record into local, or counts why it is not usage.
func (u *UsageCollector) fileEvent(ev *ctEvent, local map[usageKey]*usageVal, widen bool, from, to time.Time, st *TrailStats, unmapped map[string]bool) {
	if ev.EventType != "AwsApiCall" || ev.EventCategory == "Insight" {
		st.Skipped++
		return
	}
	if ev.ErrorCode != "" {
		st.Failed++ // a denied or failed call is not use of a permission
		return
	}
	p, ok := principalARN(ev.UserIdentity)
	if !ok {
		st.Skipped++
		return
	}
	at, ok := parseEventTime(ev.EventTime)
	if !ok || at.Before(from) || at.After(to) {
		st.Skipped++
		return
	}
	action, ok := u.Mapper.Map(ev.EventSource, ev.EventName)
	if !ok {
		st.Unmapped++
		if len(unmapped) < maxUnmapped && eventSourceRE.MatchString(ev.EventSource) && eventNameRE.MatchString(ev.EventName) {
			unmapped[strings.TrimSuffix(ev.EventSource, ".amazonaws.com")+":"+ev.EventName] = true
		}
		return
	}
	k := usageKey{principal: p, action: action, scope: resourceScope(ev.Resources, widen), day: at.Format(dayLayout)}
	v := local[k]
	if v == nil {
		v = &usageVal{}
		local[k] = v
	}
	v.count++
	if at.After(v.last) {
		v.last = at
	}
	st.Counted++
}

// plausibleKeyDay says whether a log key tail (yyyy/mm/dd/...) names a real
// day no later than tomorrow (UTC).
func plausibleKeyDay(tail string, now time.Time) bool {
	d, err := time.Parse("2006/01/02", tail[:10])
	return err == nil && !d.After(now.UTC().Add(24*time.Hour))
}

// accessHint adds to an access error what the customer must grant.
func (u *UsageCollector) accessHint(err error, t *CloudTrailConfig) string {
	msg := clip(err.Error(), 150)
	if IsAccessDenied(err) || IsCode(err, "KMS.AccessDeniedException", "AccessDeniedException") || strings.Contains(strings.ToLower(err.Error()), "kms") {
		msg += "; the reader role needs s3:ListBucket and s3:GetObject on the log prefix (TrailReaderPolicy)"
		if t.KMSKeyARN != "" {
			msg += " and kms:Decrypt on " + t.KMSKeyARN + " in the key policy"
		}
	}
	return msg
}

type gapRecorder func(source, ref, code, detail, day string)

// dataEvents reads the trail's event selectors and returns the S3 data events
// state, recording a gap unless they are fully enabled.
func (u *UsageCollector) dataEvents(ctx context.Context, col *Collector, cache map[string]*accountSession, t *CloudTrailConfig, gap gapRecorder, clear *[]string) string {
	const ref = "data_events"
	region, account := t.trailParts()
	if region == "" {
		gap(store.AWSUsageCloudTrail, ref, "data_events_unknown", "no trail_arn is configured, so it is not known whether S3 data events are logged", "")
		return store.AWSDataEventsUnknown
	}
	s, err := col.assume(ctx, cache, account)
	if err != nil {
		gap(store.AWSUsageCloudTrail, ref, "data_events_unknown", "cannot assume the reader role in the trail's account: "+errDetail(err), "")
		return store.AWSDataEventsUnknown
	}
	sel, err := s.session.getEventSelectors(ctx, region, t.TrailARN)
	if err != nil {
		gap(store.AWSUsageCloudTrail, ref, "data_events_unknown", "cloudtrail GetEventSelectors: "+errDetail(err), "")
		return store.AWSDataEventsUnknown
	}
	state, detail := sel.s3DataEvents()
	if state == store.AWSDataEventsEnabled {
		*clear = append(*clear, ref)
	} else {
		gap(store.AWSUsageCloudTrail, ref, "data_events_"+state, detail, "")
	}
	return state
}

// ---------------------------------------------------------------- Access Advisor

type advisorCursor struct {
	// After is the last principal ARN read in this round; "" starts a round.
	After string `json:"after"`
	// DoneAt is when the last round finished (RFC 3339).
	DoneAt string `json:"done_at,omitempty"`
}

func isThrottle(err error) bool {
	var ae *Error
	return errors.As(err, &ae) && (throttleCodes[ae.Code] || ae.Status == 429)
}

// collectAdvisor reads Access Advisor for up to AdvisorPerRun principals (user
// and role ARNs, sorted), continuing a round from the cursor. A round that has
// finished rests a day. Calls are paced, throttling is backed off by the
// client, and a throttle that outlasts the backoff ends the run (the cursor
// stays at the last principal read).
func (u *UsageCollector) collectAdvisor(ctx context.Context, connectorID string, principals []string, prior *store.AWSUsageState) (*usageBatch, *AdvisorStats, error) {
	now := u.now()
	var cur advisorCursor
	if prior != nil && len(prior.Cursor) > 0 {
		_ = json.Unmarshal(prior.Cursor, &cur) // unreadable: starts a round
	}
	st := &AdvisorStats{}
	b := &usageBatch{set: true, state: store.AWSUsageState{ConnectorID: connectorID, Source: store.AWSUsageAccessAdvisor, S3DataEvents: store.AWSDataEventsUnknown, UpdatedAt: now}}
	if prior != nil {
		b.state.CoveredFrom, b.state.CoveredTo = prior.CoveredFrom, prior.CoveredTo
	}
	if cur.After == "" && cur.DoneAt != "" {
		if done, err := time.Parse(time.RFC3339, cur.DoneAt); err == nil && now.Sub(done) < advisorEvery {
			st.Resting = true
			return nil, st, nil
		}
	}
	gap := func(ref, code, detail string) {
		b.gaps = append(b.gaps, store.AWSUsageGap{ConnectorID: connectorID, Source: store.AWSUsageAccessAdvisor, Ref: ref, Code: code, Detail: clip(detail, 300), RecordedAt: now})
	}
	finish := func(err error) (*usageBatch, *AdvisorStats, error) {
		raw, merr := json.Marshal(cur)
		if merr != nil {
			return b, st, errors.Join(err, merr)
		}
		b.state.Cursor = raw
		st.Rows, st.Gaps = len(b.rows), len(b.gaps)
		return b, st, err
	}
	todo := principals[sort.SearchStrings(principals, cur.After):]
	if cur.After != "" && len(todo) > 0 && todo[0] == cur.After {
		todo = todo[1:]
	}
	per := u.Config.Usage.AdvisorPerRun
	if per <= 0 {
		per = DefaultAdvisorPerRun
	}
	col, cache := u.collector()
	fails, notReady := 0, 0
	assumeErr := map[string]error{} // an account whose role cannot be assumed is not asked again for each principal
	for i, arn := range todo {
		if st.Principals >= per || (st.Principals > 0 && u.now().Sub(now) >= advisorRunBudget) {
			st.Remaining = len(todo) - i
			return finish(nil)
		}
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		if st.Principals > 0 {
			if err := u.Client.sleep(ctx, advisorPace); err != nil {
				return finish(err)
			}
		}
		parts := strings.Split(arn, ":")
		if len(parts) < 6 || !accountRE.MatchString(parts[4]) {
			cur.After = arn
			continue
		}
		err := assumeErr[parts[4]]
		var s *accountSession
		if err == nil {
			s, err = col.assume(ctx, cache, parts[4])
		}
		if err != nil {
			if ctx.Err() != nil {
				return finish(ctx.Err())
			}
			assumeErr[parts[4]] = err
			gap(arn, errCode(err), "cannot assume the reader role: "+errDetail(err))
			cur.After = arn
			continue
		}
		st.Principals++
		rep, err := s.session.serviceLastAccessed(ctx, arn)
		switch {
		case err == nil:
			fails, notReady = 0, 0
			u.advisorRows(connectorID, arn, rep, b, now)
			b.clear = append(b.clear, arn)
		case ctx.Err() != nil:
			return finish(ctx.Err())
		case IsCode(err, "NoSuchEntity"):
			// deleted since the snapshot: nothing to read, and the next snapshot drops it
			b.clear = append(b.clear, arn)
		case isThrottle(err):
			gap(arn, "rate_limited", "IAM throttled the request beyond the retry budget; the principal is read in a later run")
			st.Remaining = len(todo) - i
			return finish(nil) // the cursor stays before this principal
		case errors.Is(err, errAdvisorNotReady):
			gap(arn, "not_ready", "the Access Advisor report did not finish in time")
			if notReady++; notReady >= advisorMaxNotReady {
				cur.After = arn
				st.Remaining = len(todo) - i - 1
				return finish(nil) // IAM is slow: the next run goes on from here
			}
		default:
			fails++
			gap(arn, errCode(err), errDetail(err))
			if fails >= 5 {
				cur.After = arn
				return finish(errors.New("awsorg: usage: Access Advisor failed for 5 principals in a row"))
			}
		}
		cur.After = arn
	}
	cur.After, cur.DoneAt = "", now.UTC().Format(time.RFC3339)
	return finish(nil)
}

// advisorRows files a report: "<service>:*" at the service's last
// authenticated day, and each tracked action at its last accessed day.
func (u *UsageCollector) advisorRows(connectorID, arn string, rep *advisorReport, b *usageBatch, now time.Time) {
	add := func(action, ts string) {
		at, err := time.Parse(time.RFC3339, ts)
		if err != nil || at.After(now.Add(24*time.Hour)) {
			return
		}
		at = at.UTC()
		b.rows = append(b.rows, &store.AWSUsageDay{ConnectorID: connectorID, PrincipalARN: arn, Action: action, ResourceScope: store.AWSUsageScopeAnywhere,
			Day: at.Format(dayLayout), Source: store.AWSUsageAccessAdvisor, Count: 1, LastSeen: at})
	}
	for _, sv := range rep.Services {
		if a, ok := ServiceAction(sv.Namespace); ok && sv.LastAuthenticated != "" {
			add(a, sv.LastAuthenticated)
		}
		for _, ac := range sv.Actions {
			if ac.LastAccessed == "" {
				continue
			}
			if a, ok := u.Mapper.advisorAction(sv.Namespace, ac.Name); ok {
				add(a, ac.LastAccessed)
			}
		}
	}
}

// advisorPrincipals lists the users and roles of a snapshot to read, sorted:
// service-linked roles are skipped (AWS manages them).
func advisorPrincipals(tx *store.TenantTx, snapshotID string) ([]string, error) {
	es, err := tx.AWSEntities(snapshotID, store.AWSEntityPrincipal)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		var p model.Principal
		if err := json.Unmarshal(e.Body, &p); err != nil {
			return nil, fmt.Errorf("awsorg: snapshot %s principal %s: %w", snapshotID, e.Key, err)
		}
		if (p.Kind == model.IAMUser || p.Kind == model.IAMRole) && !p.IsServiceLinked && iamPrincipalRE.MatchString(p.ARN) {
			out = append(out, p.ARN)
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}
