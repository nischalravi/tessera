package devidp

import (
	"bytes"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const pageStyle = `body{font:15px/1.45 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}
.dev{background:#fff4ce;border:1px solid #e0b100;padding:.5rem .75rem;border-radius:6px}
fieldset{border:1px solid #d0d7de;border-radius:6px;margin:1rem 0}
button{margin:.2rem .3rem .2rem 0;padding:.35rem .7rem;border-radius:6px;border:1px solid #8c959f;background:#f6f8fa;cursor:pointer}
code{background:#f6f8fa;padding:0 .25rem;border-radius:4px}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}button,code{background:#161b22;color:#e6edf3}.dev{background:#3b2e00;color:#f5e6a8}}`

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · Tessera dev IdP</title><style>` + pageStyle + `</style></head><body>
<p class="dev"><strong>Tessera dev IdP.</strong> For local development and tests only. Nothing here is a real identity.</p>
<h1>{{.Title}}</h1>
{{if .Message}}<p>{{.Message}}</p>{{end}}
{{if .Req}}
<p>{{if .SAML}}Service provider{{else}}Client{{end}} <code>{{.ClientID}}</code> asks you to sign in.
{{if .ACRValues}} Requested <code>{{if .SAML}}AuthnContextClassRef {{else}}acr_values={{end}}{{.ACRValues}}</code>.{{end}}
{{if .ACRS}} Requested Entra auth context <code>{{.ACRS}}</code>.{{end}}
{{if .MaxAge}} <code>max_age={{.MaxAge}}</code>.{{end}}
{{if .Fault}} <strong>Fault: <code>{{.Fault}}</code></strong>.{{end}}</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="req" value="{{.Req}}">
{{if .Profiles}}<fieldset><legend>Emulate</legend>
{{range .Profiles}}<label><input type="radio" name="profile" value="{{.Value}}"{{if .Checked}} checked{{end}}> {{.Label}}</label><br>{{end}}
</fieldset>{{end}}
{{range .Users}}<fieldset><legend>{{.Name}} · <code>{{.Sub}}</code> · {{.Email}} · tenant <code>{{.Tenant}}</code>{{if .Roles}} · {{.Roles}}{{end}}</legend>
{{$u := .}}{{range .Methods}}<button type="submit" name="choice" value="{{$u.Sub}} {{.Value}}">{{.Label}}</button>{{end}}
</fieldset>{{end}}
<button type="submit" name="action" value="cancel">Cancel</button>
</form>
{{end}}
</body></html>`))

type option struct {
	Value, Label string
	Checked      bool
}

type userView struct {
	Sub, Email, Name, Tenant, Roles string
	Methods                         []option
}

type pageData struct {
	Title, Message                 string
	Req, Action, ClientID          string
	ACRValues, ACRS, MaxAge, Fault string
	Profiles                       []option
	Users                          []userView
	SAML                           bool
}

func (s *Server) renderSignIn(w http.ResponseWriter, id string, p pendingAuthz) {
	d := pageData{Title: "Sign in", Req: id, Action: s.issuer + pathAuthorize, ClientID: p.clientID,
		ACRValues: strings.Join(p.req.acrValues, " "), ACRS: strings.Join(p.req.entraACRS, " "), Fault: string(p.fault)}
	if p.hasMaxAge {
		d.MaxAge = strconv.Itoa(p.maxAge)
	}
	for _, pr := range Profiles() {
		d.Profiles = append(d.Profiles, option{Value: string(pr), Label: pr.Label(), Checked: pr == s.defaultProfile})
	}
	s.renderUsers(w, &d, p.loginHint)
}

// renderUsers adds the users (hint first) to d and renders the sign-in page.
func (s *Server) renderUsers(w http.ResponseWriter, d *pageData, loginHint string) {
	p := struct{ loginHint string }{loginHint}
	// login_hint preselects: the hinted user is listed first.
	users := s.userList()
	slices.SortStableFunc(users, func(a, b User) int {
		ha, hb := p.loginHint != "" && a.matchesHint(p.loginHint), p.loginHint != "" && b.matchesHint(p.loginHint)
		switch {
		case ha && !hb:
			return -1
		case hb && !ha:
			return 1
		}
		return 0
	})
	for _, u := range users {
		v := userView{Sub: u.Sub, Email: u.Email, Name: u.Name, Tenant: u.Tenant, Roles: strings.Join(u.Roles, ", ")}
		for _, m := range Methods() {
			if u.has(m) {
				v.Methods = append(v.Methods, option{Value: string(m), Label: m.Label()})
			}
		}
		d.Users = append(d.Users, v)
	}
	s.render(w, http.StatusOK, *d)
}

func (s *Server) errorPage(w http.ResponseWriter, status int, msg string) {
	s.render(w, status, pageData{Title: "Sign-in error", Message: msg})
}

func (s *Server) renderMessage(w http.ResponseWriter, status int, title, msg string) {
	s.render(w, status, pageData{Title: title, Message: msg})
}

func (s *Server) render(w http.ResponseWriter, status int, d pageData) {
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, d); err != nil {
		s.log.Error("devidp: rendering page", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.renderMessage(w, http.StatusOK, "Tessera dev IdP",
		"OpenID Connect discovery is at "+s.issuer+"/.well-known/openid-configuration. Sign in from the Tessera app.")
}
