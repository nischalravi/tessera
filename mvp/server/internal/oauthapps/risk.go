package oauthapps

import (
	"sort"
	"strings"
	"time"
)

// CatalogVersion is the version of the scope catalog below. Bump it when a
// scope is added or a severity changes, so a stored score can be traced to the
// table that produced it.
const CatalogVersion = "2026.10.1"

// Severities, highest first.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

// ScopeRisk is the catalog entry of one scope.
type ScopeRisk struct {
	Severity string
	Reason   string
}

// sevWeight orders severities and gives the base score of the worst scope.
var sevWeight = map[string]int{SevCritical: 60, SevHigh: 40, SevMedium: 20, SevLow: 5}

// catalog maps "provider|scope" to its risk. It is a defensive table used to
// flag grants in the customer's own tenant.
var catalog = map[string]ScopeRisk{
	// Google
	Google + "|https://mail.google.com/":                              {SevCritical, "full access to all mail"},
	Google + "|https://www.googleapis.com/auth/gmail.modify":          {SevHigh, "reads and changes all mail"},
	Google + "|https://www.googleapis.com/auth/gmail.readonly":        {SevHigh, "reads all mail"},
	Google + "|https://www.googleapis.com/auth/gmail.send":            {SevMedium, "sends mail as the user"},
	Google + "|https://www.googleapis.com/auth/drive":                 {SevHigh, "reads and changes all Drive files"},
	Google + "|https://www.googleapis.com/auth/drive.readonly":        {SevMedium, "reads all Drive files"},
	Google + "|https://www.googleapis.com/auth/drive.file":            {SevLow, "reads files the app created or opened"},
	Google + "|https://www.googleapis.com/auth/admin.directory.user":  {SevCritical, "manages all users in the directory"},
	Google + "|https://www.googleapis.com/auth/admin.directory.group": {SevHigh, "manages groups"},
	Google + "|https://www.googleapis.com/auth/calendar":              {SevMedium, "reads and changes all calendars"},
	Google + "|https://www.googleapis.com/auth/contacts":              {SevMedium, "reads and changes contacts"},
	Google + "|https://www.googleapis.com/auth/userinfo.email":        {SevLow, "reads the email address"},
	Google + "|openid":  {SevLow, "sign-in identity only"},
	Google + "|profile": {SevLow, "reads basic profile"},
	// Entra (Microsoft Graph)
	Entra + "|Directory.ReadWrite.All":            {SevCritical, "reads and writes the whole directory"},
	Entra + "|RoleManagement.ReadWrite.Directory": {SevCritical, "assigns directory roles"},
	Entra + "|Application.ReadWrite.All":          {SevCritical, "manages all app registrations"},
	Entra + "|AppRoleAssignment.ReadWrite.All":    {SevCritical, "grants app roles to any app"},
	Entra + "|Mail.ReadWrite":                     {SevHigh, "reads and changes all mail"},
	Entra + "|Mail.Read":                          {SevHigh, "reads all mail"},
	Entra + "|Mail.Send":                          {SevMedium, "sends mail as the user"},
	Entra + "|Files.ReadWrite.All":                {SevHigh, "reads and changes all files"},
	Entra + "|Files.Read.All":                     {SevMedium, "reads all files"},
	Entra + "|Sites.FullControl.All":              {SevHigh, "full control of all sites"},
	Entra + "|User.Read.All":                      {SevMedium, "reads all user profiles"},
	Entra + "|Directory.Read.All":                 {SevMedium, "reads the whole directory"},
	Entra + "|offline_access":                     {SevLow, "keeps access after sign-out"},
	Entra + "|User.Read":                          {SevLow, "reads the signed-in user profile"},
	Entra + "|openid":                             {SevLow, "sign-in identity only"},
	// Salesforce
	Salesforce + "|full":           {SevCritical, "full access as the user"},
	Salesforce + "|api":            {SevHigh, "API access to data as the user"},
	Salesforce + "|refresh_token":  {SevMedium, "keeps access without the user"},
	Salesforce + "|offline_access": {SevMedium, "keeps access without the user"},
	Salesforce + "|web":            {SevMedium, "web session access as the user"},
	Salesforce + "|id":             {SevLow, "reads the user identity"},
	Salesforce + "|openid":         {SevLow, "sign-in identity only"},
	// GitHub
	GitHub + "|admin:org":            {SevCritical, "full organization administration"},
	GitHub + "|delete_repo":          {SevCritical, "deletes repositories"},
	GitHub + "|repo":                 {SevHigh, "full repository read and write"},
	GitHub + "|workflow":             {SevHigh, "changes workflow files"},
	GitHub + "|write:packages":       {SevHigh, "publishes packages"},
	GitHub + "|read:org":             {SevMedium, "reads organization membership"},
	GitHub + "|contents:write":       {SevHigh, "writes repository contents"},
	GitHub + "|administration:write": {SevCritical, "administers repositories"},
	GitHub + "|contents:read":        {SevMedium, "reads repository contents"},
	GitHub + "|metadata:read":        {SevLow, "reads repository metadata"},
	GitHub + "|read:user":            {SevLow, "reads the user profile"},
	GitHub + "|user:email":           {SevLow, "reads the email address"},
}

// LookupScope returns the catalog entry of a scope. An unknown scope is low,
// with a reason that says so, so a new scope never scores as nothing.
func LookupScope(provider, scope string) ScopeRisk {
	if r, ok := catalog[provider+"|"+scope]; ok {
		return r
	}
	return ScopeRisk{SevLow, "scope not in the catalog"}
}

// Score modifiers.
const (
	// UnusedDays is the age after which an app counts as unused for scoring.
	UnusedDays = 90

	modUnverified = 15
	modAdmin      = 10
	modUnused     = 10
	modUsersMid   = 5  // 10 or more users
	modUsersHigh  = 10 // 100 or more users
)

// Assessment is the risk of one app.
type Assessment struct {
	Score    int      // 0-100
	Severity string   // worst scope severity: critical, high, medium, low
	Reasons  []string // sorted, no duplicates
}

// Subject is what Assess needs to know about an app.
type Subject struct {
	Provider   string
	Scopes     []string
	Verified   bool
	AdminGrant bool // some grant is tenant-wide admin consent
	LastUsed   *time.Time
	Users      int
}

// Assess scores an app 0-100: the worst scope sets the base, then modifiers
// add for an unverified publisher, tenant-wide admin consent, 90 or more days
// unused, and the number of users.
func Assess(s Subject, now time.Time) Assessment {
	worst := ""
	reasons := map[string]bool{}
	for _, sc := range s.Scopes {
		r := LookupScope(s.Provider, sc)
		if worst == "" || sevWeight[r.Severity] > sevWeight[worst] {
			worst = r.Severity
		}
		if r.Severity == SevCritical || r.Severity == SevHigh {
			reasons[sc+": "+r.Reason] = true
		}
	}
	if worst == "" {
		worst = SevLow
	}
	score := sevWeight[worst]
	if !s.Verified {
		score += modUnverified
		reasons["unverified publisher"] = true
	}
	if s.AdminGrant {
		score += modAdmin
		reasons["tenant-wide admin consent"] = true
	}
	if s.LastUsed != nil && now.Sub(*s.LastUsed) >= UnusedDays*24*time.Hour {
		score += modUnused
		reasons["unused for 90 days or more"] = true
	}
	switch {
	case s.Users >= 100:
		score += modUsersHigh
		reasons["granted by 100 or more users"] = true
	case s.Users >= 10:
		score += modUsersMid
		reasons["granted by 10 or more users"] = true
	}
	if score > 100 {
		score = 100
	}
	out := make([]string, 0, len(reasons))
	for r := range reasons {
		out = append(out, r)
	}
	sort.Strings(out)
	return Assessment{Score: score, Severity: worst, Reasons: out}
}

// IsHighRisk reports whether a severity is high or critical.
func IsHighRisk(severity string) bool {
	return strings.EqualFold(severity, SevHigh) || strings.EqualFold(severity, SevCritical)
}
