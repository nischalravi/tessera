package api

import (
	"net/http"
	"slices"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/mfa"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// MFA posture report (issue #109): coverage by department and privileged
// group, passkey enrolment over time, per-identity methods, and apps that
// bypass SSO or MFA. It reads what the Okta and Entra connectors registered;
// a system that could not read its methods is listed under "sources" and its
// people are "unknown", never "no MFA".

func (s *Server) registerMFARoutes() {
	s.handle(http.MethodGet, "/api/mfa/posture", read, need(auth.PermGraphRead), s.mfaPosture)
}

// maxDepartmentFilter bounds the department query value.
const maxDepartmentFilter = 200

type mfaTrendPoint struct {
	Date              string `json:"date"`
	Total             int    `json:"total"`
	PhishingResistant int    `json:"phishing_resistant"`
	PushNumberMatch   int    `json:"push_number_match"`
	Push              int    `json:"push"`
	OTP               int    `json:"otp"`
	SMSVoice          int    `json:"sms_voice"`
	NoMFA             int    `json:"no_mfa"`
	Unknown           int    `json:"unknown"`
	PasskeyEnrolled   int    `json:"passkey_enrolled"`
}

type mfaPosture struct {
	AsOf        string             `json:"as_of"`
	Departments []string           `json:"departments"` // every department, for the filter chips
	Sources     []mfa.Source       `json:"sources"`
	Summary     mfa.Summary        `json:"summary"`
	Trend       []mfaTrendPoint    `json:"trend"`
	Identities  []*mfa.Identity    `json:"identities"`
	AppFindings []mfa.AppFinding   `json:"app_findings"`
	AppSystems  []mfa.AppSystem    `json:"app_systems"`
	Classes     []mfaClassDescribe `json:"classes"`
}

type mfaClassDescribe struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

func (s *Server) mfaPosture(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	department := p.queryOptStr("department")
	privileged := p.queryOptBool("privileged")
	var more []verr
	if department != nil && len(*department) > maxDepartmentFilter {
		more = append(more, verr{Type: "string_too_long", Loc: []any{"query", "department"},
			Msg: "String should have at most 200 characters", Input: *department})
	}
	if err := validated(p, more); err != nil {
		return nil, err
	}
	now := s.clock()
	data, err := mfa.Load(store.TxFrom(r.Context()), now)
	if err != nil {
		return nil, err
	}
	out := mfaPosture{AsOf: timeutil.ISO(now), Departments: []string{}, Sources: data.Sources, Trend: []mfaTrendPoint{},
		Identities: []*mfa.Identity{}, AppFindings: []mfa.AppFinding{}, AppSystems: data.Apps}
	if out.Sources == nil {
		out.Sources = []mfa.Source{}
	}
	if out.AppSystems == nil {
		out.AppSystems = []mfa.AppSystem{}
	}
	for _, c := range mfa.Strengths {
		out.Classes = append(out.Classes, mfaClassDescribe{Key: string(c), Label: c.Label()})
	}
	for _, v := range data.Identities {
		if !slices.Contains(out.Departments, v.Department) {
			out.Departments = append(out.Departments, v.Department)
		}
		if (nonEmpty(department) && v.Department != *department) || (privileged != nil && v.Privileged != *privileged) {
			continue
		}
		out.Identities = append(out.Identities, v)
	}
	slices.Sort(out.Departments)
	out.Summary = mfa.Summarize(out.Identities)
	for _, f := range data.Findings {
		if privileged == nil || f.Privileged == *privileged {
			out.AppFindings = append(out.AppFindings, f)
		}
	}
	for _, t := range data.Trend {
		out.Trend = append(out.Trend, mfaTrendPoint{Date: t.Date, Total: t.Total, PhishingResistant: t.PhishingResistant,
			PushNumberMatch: t.PushNumberMatch, Push: t.Push, OTP: t.OTP, SMSVoice: t.SMSVoice, NoMFA: t.NoMFA,
			Unknown: t.Unknown, PasskeyEnrolled: t.PasskeyEnrolled})
	}
	return out, nil
}
