// Package evidence builds framework evidence packs: a ZIP of the access
// evidence an auditor asks for (user listing, joiner-mover-leaver timings,
// review campaigns, privileged access, revocations) with a SHA-256 manifest.
//
// The control mappings follow docs/knowledge/04-identity-governance-and-compliance.md
// section 3. A pack is evidence of what Tessera knew when it was generated:
// grants are point-in-time (edge_history); identities, accounts and campaigns
// are current records filtered to the period.
package evidence

// Control maps one framework control to the files of a pack that evidence it.
type Control struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	Files []string `json:"files"`
}

// Framework is a compliance framework a pack can be generated for.
type Framework struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Controls []Control `json:"controls"`
	// Notes are framework-specific caveats printed in the pack's README.
	Notes []string `json:"notes"`
}

// The pack's files (see Generate).
const (
	FileUsers      = "users.csv"
	FileJML        = "jml_leavers.csv"
	FileCampaigns  = "review_campaigns.csv"
	FileItems      = "review_items.csv"
	FilePrivileged = "privileged_access.csv"
	FileRevoked    = "revocations.csv"
	// FileQuestionnaires holds the answers given to questionnaires on requests and review decisions (issue #298).
	FileQuestionnaires = "questionnaire_answers.csv"
)

var frameworks = []Framework{
	{ID: "soc2", Name: "SOC 2 (Trust Services Criteria)", Controls: []Control{
		{"CC6.1", "Logical access: identification, authentication, restriction", []string{FileUsers, FilePrivileged}},
		{"CC6.2", "Registration and authorization before credentials; removal when access is no longer needed", []string{FileUsers, FileJML, FileQuestionnaires}},
		{"CC6.3", "Access modification and removal; periodic review", []string{FileJML, FileCampaigns, FileItems, FileRevoked}},
	}, Notes: []string{"SOC 2 sets no review frequency; the auditor tests the one the company defines."}},
	{ID: "sox_itgc", Name: "SOX ITGC (logical access)", Controls: []Control{
		{"ITGC-Provisioning", "New access approved before grant", []string{FileUsers, FileQuestionnaires}},
		{"ITGC-Termination", "Terminated users removed timely", []string{FileJML, FileRevoked}},
		{"ITGC-Review", "Periodic user access recertification", []string{FileCampaigns, FileItems}},
		{"ITGC-Privileged", "Privileged access restricted and reviewed", []string{FilePrivileged}},
	}, Notes: []string{"'Timely' is defined by the company (commonly 1 to 5 business days); the JML file reports the measured hours."}},
	{ID: "iso27001", Name: "ISO/IEC 27001:2022 Annex A", Controls: []Control{
		{"A.5.15", "Access control", []string{FileUsers}},
		{"A.5.16", "Identity management", []string{FileUsers}},
		{"A.5.18", "Access rights: provisioning, review, removal", []string{FileJML, FileCampaigns, FileItems, FileRevoked, FileQuestionnaires}},
		{"A.8.2", "Privileged access rights", []string{FilePrivileged}},
	}, Notes: nil},
	{ID: "pci_dss_v4", Name: "PCI DSS v4.0.1 (requirements 7 and 8)", Controls: []Control{
		{"7.2.4", "All user accounts and access privileges reviewed at least every six months", []string{FileCampaigns, FileItems, FileUsers}},
		{"8.2.5", "Access for terminated users immediately revoked", []string{FileJML, FileRevoked}},
		{"7.2.2", "Access assigned by job function and least privilege", []string{FilePrivileged}},
	}, Notes: []string{
		"PCI 7.2.4 requires every user account to be reviewed with management acknowledgement. Tessera's campaigns " +
			"are exception-only: review_campaigns.csv shows the auto-certified count, which an assessor may not accept for in-scope systems.",
	}},
}

// Frameworks lists the supported frameworks.
func Frameworks() []Framework { return append([]Framework(nil), frameworks...) }

// Lookup returns the framework with the id.
func Lookup(id string) (Framework, bool) {
	for _, f := range frameworks {
		if f.ID == id {
			return f, true
		}
	}
	return Framework{}, false
}

// IDs lists the framework ids, in display order.
func IDs() []string {
	out := make([]string, len(frameworks))
	for i, f := range frameworks {
		out[i] = f.ID
	}
	return out
}
