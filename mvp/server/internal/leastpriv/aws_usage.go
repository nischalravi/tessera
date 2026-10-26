package leastpriv

import (
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// UsedCallsFromUsage turns the AWS usage rows of one principal (aws_usage_daily:
// CloudTrail and Access Advisor, issue #644) into the calls VerifyAWS keeps. A
// call is an (action, resource scope) pair seen on any day of the rows; the
// actions are already in the evaluator's spelling (the ingest maps them through
// the action catalog), and the resource is the row's scope: an ARN, or "*" when
// the log named no resource.
//
// Service-level rows ("s3:*", all Access Advisor can say for most services)
// are left out: they say the service was used, not which call, so they cannot
// be kept or broken as a call. They are still usage, and a caller that wants
// "was anything of this service used" reads them from the rows.
func UsedCallsFromUsage(rows []*store.AWSUsageDay) []UsedCall {
	seen := map[UsedCall]bool{}
	var out []UsedCall
	for _, r := range rows {
		if strings.HasSuffix(r.Action, ":*") {
			continue
		}
		c := UsedCall{Action: r.Action, Resource: r.ResourceScope}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Action+"\x00"+out[i].Resource < out[j].Action+"\x00"+out[j].Resource
	})
	return out
}
