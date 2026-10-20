package benchgen

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Markdown writes the report as the table of the design's section 6.7: one row
// per target with the measured value, the limit and PASS or FAIL.
func (r *Report) Markdown(w io.Writer) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Groups scale gate: %.4g%% of the reference tenant on %s, %s\n\n", r.Percent, r.Backend, r.Started.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(&b, "Tenant: %s\n\n", r.Stats)
	b.WriteString("| Target | Stat | Measured | Limit | Result | Note |\n|---|---|---|---|---|---|\n")
	for _, x := range r.Results {
		limit, verdict := "none", "reported"
		if x.Limit != 0 {
			limit, verdict = fmt.Sprintf("%g %s", x.Limit, x.Unit), "PASS"
			if !x.Pass {
				verdict = "FAIL"
			}
		} else if !x.Pass { // a check with a zero limit, such as "no repairs"
			verdict = "FAIL"
		} else if x.Stat == "repairs" {
			limit, verdict = "0", "PASS"
		}
		fmt.Fprintf(&b, "| %s | %s | %.4g %s | %s | %s | %s |\n", x.Design, x.Stat, x.Value, x.Unit, limit, verdict, x.Note)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// JSON writes the report as JSON, for a dashboard or a trend.
func (r *Report) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
