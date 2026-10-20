package flatfile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// File kinds.
const (
	KindAccounts     = "accounts"
	KindEntitlements = "entitlements"
)

// AccountCols maps the columns of an accounts file. AccountID and Username
// are required; the others are optional ("" leaves a field unmapped).
// IdentityID and Email are how the account is correlated to a person (the
// identity's external id first, then email, as for every connector).
type AccountCols struct {
	AccountID  string `json:"account_id"`
	Username   string `json:"username"`
	Email      string `json:"email,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
	Status     string `json:"status,omitempty"`
}

// EntitlementCols maps the columns of an account-entitlement file: one row
// per account and entitlement. AccountID and Entitlement are required.
type EntitlementCols struct {
	AccountID   string `json:"account_id"`
	Entitlement string `json:"entitlement"`
	Name        string `json:"name,omitempty"`
	Privileged  string `json:"privileged,omitempty"`
}

// Mapping is the saved column mapping of one disconnected app.
type Mapping struct {
	System       string
	Name         string
	Owner        string
	Accounts     AccountCols
	Entitlements *EntitlementCols // nil: the app has no entitlement file
}

var systemRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

// ValidSystem reports whether s is a usable system name for a disconnected app.
func ValidSystem(s string) bool { return systemRE.MatchString(s) }

// FieldError names the field of a mapping that is wrong.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

func validColumn(field, v string, required bool) error {
	switch {
	case v == "" && required:
		return &FieldError{field, "a column name is required"}
	case v == "":
		return nil
	case utf8.RuneCountInString(v) > 100 || strings.TrimSpace(v) != v || strings.IndexFunc(v, unicode.IsControl) >= 0:
		return &FieldError{field, "must be a column name of at most 100 characters, without control characters or surrounding spaces"}
	}
	return nil
}

// Validate checks the mapping: a valid system, names, and the required
// columns; a column may not serve two fields of one file.
func (m *Mapping) Validate() error {
	if !ValidSystem(m.System) {
		return &FieldError{"system", "use 1 to 63 lower-case letters, digits, '.', '_' or '-', starting with a letter or digit"}
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(m.Name)); n < 1 || n > 100 || strings.IndexFunc(m.Name, unicode.IsControl) >= 0 {
		return &FieldError{"name", "required: 1 to 100 characters"}
	}
	if utf8.RuneCountInString(m.Owner) > 200 || strings.IndexFunc(m.Owner, unicode.IsControl) >= 0 {
		return &FieldError{"owner", "at most 200 characters"}
	}
	a := m.Accounts
	for _, c := range []struct {
		field, v string
		req      bool
	}{{"accounts.account_id", a.AccountID, true}, {"accounts.username", a.Username, true}, {"accounts.email", a.Email, false},
		{"accounts.identity_id", a.IdentityID, false}, {"accounts.status", a.Status, false}} {
		if err := validColumn(c.field, c.v, c.req); err != nil {
			return err
		}
	}
	if err := distinct("accounts", a.AccountID, a.Username, a.Email, a.IdentityID, a.Status); err != nil {
		return err
	}
	if e := m.Entitlements; e != nil {
		for _, c := range []struct {
			field, v string
			req      bool
		}{{"entitlements.account_id", e.AccountID, true}, {"entitlements.entitlement", e.Entitlement, true},
			{"entitlements.name", e.Name, false}, {"entitlements.privileged", e.Privileged, false}} {
			if err := validColumn(c.field, c.v, c.req); err != nil {
				return err
			}
		}
		if err := distinct("entitlements", e.AccountID, e.Entitlement, e.Name, e.Privileged); err != nil {
			return err
		}
	}
	return nil
}

func distinct(file string, cols ...string) error {
	seen := map[string]bool{}
	for _, c := range cols {
		if c == "" {
			continue
		}
		k := strings.ToLower(c)
		if seen[k] {
			return &FieldError{file, fmt.Sprintf("the column %q serves two fields", c)}
		}
		seen[k] = true
	}
	return nil
}

// ToStore is the saved form of the mapping.
func (m *Mapping) ToStore() (*store.FlatMapping, error) {
	ac, err := json.Marshal(m.Accounts)
	if err != nil {
		return nil, err
	}
	out := &store.FlatMapping{System: m.System, Name: strings.TrimSpace(m.Name), Owner: strings.TrimSpace(m.Owner), AccountCols: string(ac)}
	if m.Entitlements != nil {
		ec, err := json.Marshal(m.Entitlements)
		if err != nil {
			return nil, err
		}
		out.EntitlementCols = string(ec)
	}
	return out, nil
}

// FromStore reads a saved mapping.
func FromStore(s *store.FlatMapping) (*Mapping, error) {
	m := &Mapping{System: s.System, Name: s.Name, Owner: s.Owner}
	if err := json.Unmarshal([]byte(s.AccountCols), &m.Accounts); err != nil {
		return nil, fmt.Errorf("flatfile: mapping %s: %w", s.System, err)
	}
	if s.EntitlementCols != "" {
		m.Entitlements = &EntitlementCols{}
		if err := json.Unmarshal([]byte(s.EntitlementCols), m.Entitlements); err != nil {
			return nil, fmt.Errorf("flatfile: mapping %s: %w", s.System, err)
		}
	}
	return m, nil
}

// Record is one validated, normalised row. Key identifies it across uploads;
// Fields are what a change is detected on; Hash covers both.
type Record struct {
	Key    string
	Label  string
	Fields map[string]string
	Hash   string
}

func newRecord(key, label string, fields map[string]string) Record {
	b, _ := json.Marshal(fields) // a map of strings always marshals; keys are sorted
	h := sha256.Sum256(append([]byte(key+"\x00"), b...))
	return Record{Key: key, Label: label, Fields: fields, Hash: hex.EncodeToString(h[:])}
}

// Data is the stored form of the fields.
func (r Record) Data() string {
	b, _ := json.Marshal(r.Fields)
	return string(b)
}

// keySep joins the parts of an entitlement record's key. Cells with control
// characters are rejected, so no value contains it.
const keySep = "\x1f"

// EntitlementKey is the record key of an account's entitlement.
func EntitlementKey(accountID, entitlement string) string { return accountID + keySep + entitlement }

// SplitEntitlementKey is the inverse of EntitlementKey.
func SplitEntitlementKey(key string) (accountID, entitlement string) {
	a, e, _ := strings.Cut(key, keySep)
	return a, e
}

// columns resolves mapped column names to indexes of the header (matching
// ignores case); a mapped column the file lacks is a file error.
type columns struct {
	idx  map[string]int
	errs []RowError
}

func resolve(header []string, mapped ...string) *columns {
	pos := map[string]int{}
	for i, h := range header {
		pos[strings.ToLower(h)] = i
	}
	c := &columns{idx: map[string]int{}}
	for _, name := range mapped {
		if name == "" {
			continue
		}
		i, ok := pos[strings.ToLower(name)]
		if !ok {
			c.errs = append(c.errs, RowError{Column: Neutralize(name), Code: CodeMissingColumn,
				Message: fmt.Sprintf("the file has no column %q, which the mapping needs", Neutralize(name))})
			continue
		}
		c.idx[name] = i
	}
	return c
}

// get returns the cell of a mapped column ("" when the column is unmapped).
func (c *columns) get(row Row, name string) string {
	if i, ok := c.idx[name]; ok {
		return row.Cells[i]
	}
	return ""
}

// show is a value for an error message: short, and safe to put in a sheet.
func show(v string) string {
	if utf8.RuneCountInString(v) > 40 {
		v = string([]rune(v)[:40]) + "..."
	}
	return Neutralize(v)
}

// checkCell is the check every mapped cell passes: bounded, and free of
// control characters (a newline in a cell would break exports and logs).
func checkCell(row int, col, v string) *RowError {
	switch {
	case utf8.RuneCountInString(v) > MaxCellRunes:
		return &RowError{Row: row, Column: col, Code: CodeTooLong, Message: fmt.Sprintf("the value is longer than %d characters", MaxCellRunes)}
	case strings.IndexFunc(v, unicode.IsControl) >= 0:
		return &RowError{Row: row, Column: col, Code: CodeControlChar, Message: "the value has a control character (such as a line break or tab)"}
	}
	return nil
}

// checkKey is the check an identifier passes: present, and not starting like
// a spreadsheet formula (identifiers are kept as they are, never rewritten).
func checkKey(row int, col, v string) *RowError {
	switch {
	case v == "":
		return &RowError{Row: row, Column: col, Code: CodeRequired, Message: "a value is required"}
	case HasFormulaPrefix(v):
		return &RowError{Row: row, Column: col, Code: CodeFormulaPrefix,
			Message: fmt.Sprintf("the value %s starts with = + - or @, which a spreadsheet would run as a formula", show(v))}
	}
	return nil
}

var (
	activeStatuses   = map[string]bool{"active": true, "enabled": true, "1": true, "true": true, "yes": true, "": true}
	disabledStatuses = map[string]bool{"disabled": true, "inactive": true, "suspended": true, "locked": true, "terminated": true,
		"deactivated": true, "0": true, "false": true, "no": true}
	trueValues  = map[string]bool{"true": true, "yes": true, "y": true, "1": true}
	falseValues = map[string]bool{"false": true, "no": true, "n": true, "0": true, "": true}
)

// AccountRecords validates an accounts file against the mapping. Every bad
// row is reported; the records are only usable when there are no errors.
func (m *Mapping) AccountRecords(t *Table) ([]Record, []RowError) {
	a := m.Accounts
	cols := resolve(t.Header, a.AccountID, a.Username, a.Email, a.IdentityID, a.Status)
	if len(cols.errs) > 0 {
		return nil, cols.errs
	}
	errs := cloneErrors(t.Short)
	var out []Record
	seen := map[string]int{}
	for _, row := range t.Rows {
		bad := false
		fail := func(e *RowError) {
			if e != nil {
				errs, bad = append(errs, *e), true
			}
		}
		for _, name := range []string{a.AccountID, a.Username, a.Email, a.IdentityID, a.Status} {
			if name != "" {
				fail(checkCell(row.Num, name, cols.get(row, name)))
			}
		}
		if bad {
			continue
		}
		id, username := cols.get(row, a.AccountID), cols.get(row, a.Username)
		email, xid, status := cols.get(row, a.Email), cols.get(row, a.IdentityID), strings.ToLower(cols.get(row, a.Status))
		fail(checkKey(row.Num, a.AccountID, id))
		if username == "" {
			fail(&RowError{Row: row.Num, Column: a.Username, Code: CodeRequired, Message: "a value is required"})
		}
		if xid != "" {
			fail(checkKey(row.Num, a.IdentityID, xid))
		}
		if email != "" {
			switch {
			case HasFormulaPrefix(email):
				fail(&RowError{Row: row.Num, Column: a.Email, Code: CodeFormulaPrefix,
					Message: fmt.Sprintf("the value %s starts with = + - or @, which a spreadsheet would run as a formula", show(email))})
			case !validEmail(email):
				fail(&RowError{Row: row.Num, Column: a.Email, Code: CodeInvalidEmail, Message: fmt.Sprintf("%s is not an email address", show(email))})
			}
		}
		norm := "active"
		switch {
		case activeStatuses[status]:
		case disabledStatuses[status]:
			norm = "disabled"
		default:
			fail(&RowError{Row: row.Num, Column: a.Status, Code: CodeInvalidStatus,
				Message: fmt.Sprintf("the status %s is not one of active, enabled, disabled, inactive, suspended, locked, terminated", show(status))})
		}
		if !bad {
			if first, dup := seen[id]; dup {
				fail(&RowError{Row: row.Num, Column: a.AccountID, Code: CodeDuplicateKey,
					Message: fmt.Sprintf("the account %s is already in row %d", show(id), first)})
			}
		}
		if bad {
			continue
		}
		seen[id] = row.Num
		out = append(out, newRecord(id, id, map[string]string{"account_id": id, "username": Neutralize(username),
			"email": strings.ToLower(email), "identity_id": xid, "status": norm}))
	}
	sortErrors(errs)
	return out, errs
}

// EntitlementRecords validates an entitlements file. knownAccounts are the
// account ids of the accounts snapshot: a row must name one of them.
func (m *Mapping) EntitlementRecords(t *Table, knownAccounts map[string]bool) ([]Record, []RowError) {
	e := m.Entitlements
	if e == nil {
		return nil, []RowError{{Code: CodeMissingColumn, Message: "the mapping has no entitlement columns"}}
	}
	cols := resolve(t.Header, e.AccountID, e.Entitlement, e.Name, e.Privileged)
	if len(cols.errs) > 0 {
		return nil, cols.errs
	}
	errs := cloneErrors(t.Short)
	var out []Record
	seen := map[string]int{}
	for _, row := range t.Rows {
		bad := false
		fail := func(x *RowError) {
			if x != nil {
				errs, bad = append(errs, *x), true
			}
		}
		for _, name := range []string{e.AccountID, e.Entitlement, e.Name, e.Privileged} {
			if name != "" {
				fail(checkCell(row.Num, name, cols.get(row, name)))
			}
		}
		if bad {
			continue
		}
		acct, ent := cols.get(row, e.AccountID), cols.get(row, e.Entitlement)
		name, priv := cols.get(row, e.Name), strings.ToLower(cols.get(row, e.Privileged))
		fail(checkKey(row.Num, e.AccountID, acct))
		fail(checkKey(row.Num, e.Entitlement, ent))
		privileged := trueValues[priv]
		if !trueValues[priv] && !falseValues[priv] {
			fail(&RowError{Row: row.Num, Column: e.Privileged, Code: CodeInvalidValue,
				Message: fmt.Sprintf("%s is not yes or no", show(priv))})
		}
		if !bad && !knownAccounts[acct] {
			fail(&RowError{Row: row.Num, Column: e.AccountID, Code: CodeUnknownAccount,
				Message: fmt.Sprintf("the account %s is not in the accounts file last uploaded", show(acct))})
		}
		key := EntitlementKey(acct, ent)
		if !bad {
			if first, dup := seen[key]; dup {
				fail(&RowError{Row: row.Num, Column: e.Entitlement, Code: CodeDuplicateKey,
					Message: fmt.Sprintf("the account %s already has %s in row %d", show(acct), show(ent), first)})
			}
		}
		if bad {
			continue
		}
		seen[key] = row.Num
		if name == "" {
			name = ent
		}
		out = append(out, newRecord(key, acct+" / "+ent, map[string]string{"account_id": acct, "entitlement": ent,
			"name": Neutralize(name), "privileged": fmt.Sprint(privileged)}))
	}
	sortErrors(errs)
	return out, errs
}

func cloneErrors(in []RowError) []RowError { return append([]RowError(nil), in...) }

func sortErrors(errs []RowError) {
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Row < errs[j].Row })
}

// validEmail is deliberately plain: one '@' with text on both sides, no
// spaces, a dot in the domain.
func validEmail(s string) bool {
	if len(s) > 254 || strings.ContainsAny(s, " ,;<>()\"\\") {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && strings.Contains(domain, ".") && !strings.Contains(domain, "@") &&
		!strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}
