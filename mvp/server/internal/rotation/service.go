package rotation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Problem is a refusal with the HTTP status the API should answer with.
type Problem struct {
	Status int
	Code   string
	Msg    string
}

func (p *Problem) Error() string { return p.Code + ": " + p.Msg }

func problem(status int, code, format string, a ...any) *Problem {
	return &Problem{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}

func invalid(code, format string, a ...any) *Problem {
	return problem(http.StatusUnprocessableEntity, code, format, a...)
}

// Service holds what the API and the JML executor need to manage rotation:
// policies, adapters, plans and the job queue. The worker that runs the jobs
// is Engine.
type Service struct {
	// Sealer seals adapter credentials (nil: adapters with credentials cannot be saved).
	Sealer *seal.Sealer
	// Env is "dev", "test" or "prod".
	Env string
	// AllowFake admits the simulated adapter (dev and test only).
	AllowFake bool
	// Notifier tells owners; nil means AuditNotifier.
	Notifier Notifier
}

func (s *Service) notifier() Notifier {
	if s.Notifier == nil {
		return AuditNotifier{}
	}
	return s.Notifier
}

func (s *Service) notify(tx *store.TenantTx, n Notification) error {
	return s.notifier().Notify(tx.Context(), tx, n)
}

func record(tx *store.TenantTx, now time.Time, action, targetType, targetID string, d ojson.Object) error {
	_, err := audit.Record(tx.Context(), tx, action, d, audit.At(now), audit.Target(targetType, targetID))
	return err
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// ---------------------------------------------------------------- adapters

// AdapterView is an adapter as the API shows it: the credential is never included.
type AdapterView struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Type          string            `json:"type"`
	Config        map[string]string `json:"config"`
	CredentialSet bool              `json:"credential_set"`
	CreatedBy     string            `json:"created_by"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

func adapterView(a *store.RotationAdapter) AdapterView {
	cfg := map[string]string{}
	_ = json.Unmarshal([]byte(a.Config), &cfg)
	return AdapterView{ID: a.ID, Name: a.Name, Type: a.Type, Config: cfg, CredentialSet: len(a.SecretEnc) > 0 && a.Type != TypeFake,
		CreatedBy: a.CreatedBy, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}

// Adapters lists the tenant's adapters.
func (s *Service) Adapters(tx *store.TenantTx) ([]AdapterView, error) {
	rows, err := tx.RotationAdapters()
	if err != nil {
		return nil, err
	}
	out := make([]AdapterView, 0, len(rows))
	for _, a := range rows {
		out = append(out, adapterView(a))
	}
	return out, nil
}

// PutAdapter creates an adapter, or updates the one with this name (its type
// cannot change; an omitted credential keeps the sealed one). The credential
// is sealed under the KEK, bound to this tenant and adapter, and is not
// returned or logged.
func (s *Service) PutAdapter(tx *store.TenantTx, in AdapterInput, actor string, now time.Time) (*AdapterView, bool, error) {
	if !nameRE.MatchString(in.Name) {
		return nil, false, invalid("invalid_name", "name must be 1 to 63 letters, digits, dots, dashes or underscores")
	}
	if in.Type == TypeFake && !s.AllowFake {
		return nil, false, invalid("adapter_type_refused", "the simulated adapter is only available in dev and test environments")
	}
	known := false
	for _, t := range AdapterTypes(s.AllowFake) {
		known = known || t == in.Type
	}
	if !known {
		return nil, false, invalid("invalid_type", "type must be one of %s", strings.Join(AdapterTypes(s.AllowFake), ", "))
	}
	cfg, err := cleanConfig(in.Type, in.Config, s.Env)
	if err != nil {
		return nil, false, invalid("invalid_config", "%v", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, false, err
	}
	existing, err := tx.RotationAdapterByName(in.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	creating := errors.Is(err, store.ErrNotFound)
	if !creating && existing.Type != in.Type {
		return nil, false, invalid("type_change", "an adapter's type cannot change; create a new adapter")
	}
	var sealed []byte
	credChanged := false
	if in.Type != TypeFake && (creating || len(in.Credential) > 0) {
		cred, err := cleanCredential(in.Type, in.Credential)
		if err != nil {
			return nil, false, invalid("invalid_credential", "%v", err)
		}
		if s.Sealer == nil {
			return nil, false, problem(http.StatusServiceUnavailable, "sealing_unavailable", "no key-encryption key is configured, so credentials cannot be stored")
		}
		credChanged = true
		plain, err := json.Marshal(cred)
		if err != nil {
			return nil, false, err
		}
		id := store.NewID()
		if !creating {
			id = existing.ID
		}
		if sealed, err = s.Sealer.Seal(plain, sealAAD(tx.Tenant(), id)); err != nil {
			return nil, false, err
		}
		if creating {
			row := &store.RotationAdapter{ID: id, TenantID: tx.Tenant(), Name: in.Name, Type: in.Type, Config: string(cfgJSON),
				SecretEnc: sealed, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
			return s.insertAdapter(tx, row, actor, now, credChanged)
		}
	} else if creating { // the simulated adapter holds no credential
		row := &store.RotationAdapter{ID: store.NewID(), TenantID: tx.Tenant(), Name: in.Name, Type: in.Type,
			Config: string(cfgJSON), SecretEnc: []byte{}, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
		return s.insertAdapter(tx, row, actor, now, false)
	}
	if sealed == nil {
		sealed = existing.SecretEnc
	}
	if err := tx.UpdateRotationAdapter(existing.ID, string(cfgJSON), sealed, now); err != nil {
		return nil, false, err
	}
	if err := record(tx, now, "rotation.adapter.updated", "rotation_adapter", existing.ID, ojson.Object{
		{Key: "name", Value: in.Name}, {Key: "type", Value: in.Type}, {Key: "credential_replaced", Value: credChanged}}); err != nil {
		return nil, false, err
	}
	row, err := tx.RotationAdapter(existing.ID)
	if err != nil {
		return nil, false, err
	}
	v := adapterView(row)
	return &v, false, nil
}

func (s *Service) insertAdapter(tx *store.TenantTx, row *store.RotationAdapter, actor string, now time.Time, credSet bool) (*AdapterView, bool, error) {
	if err := tx.InsertRotationAdapter(row); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, false, problem(http.StatusConflict, "duplicate", "an adapter named %q already exists", row.Name)
		}
		return nil, false, err
	}
	if err := record(tx, now, "rotation.adapter.created", "rotation_adapter", row.ID, ojson.Object{
		{Key: "name", Value: row.Name}, {Key: "type", Value: row.Type}, {Key: "credential_set", Value: credSet}}); err != nil {
		return nil, false, err
	}
	v := adapterView(row)
	return &v, true, nil
}

// DeleteAdapter removes an adapter no policy or job refers to.
func (s *Service) DeleteAdapter(tx *store.TenantTx, id string, actor string, now time.Time) error {
	row, err := tx.RotationAdapter(id)
	if errors.Is(err, store.ErrNotFound) {
		return problem(http.StatusNotFound, "not_found", "no such adapter")
	}
	if err != nil {
		return err
	}
	n, err := tx.RotationAdapterUses(id)
	if err != nil {
		return err
	}
	if n > 0 {
		return problem(http.StatusConflict, "adapter_in_use", "%d polic(ies) and job(s) refer to this adapter; remove the policies first (finished jobs keep it as history, so replace its credential instead)", n)
	}
	if _, err := tx.DeleteRotationAdapter(id); err != nil {
		return err
	}
	return record(tx, now, "rotation.adapter.deleted", "rotation_adapter", id, ojson.Object{
		{Key: "name", Value: row.Name}, {Key: "type", Value: row.Type}})
}

// ---------------------------------------------------------------- policies

// PolicyInput is a policy as submitted. Adapter and Destination are adapter names.
type PolicyInput struct {
	Kind        string  `json:"kind"`
	System      string  `json:"system"`
	MaxAgeDays  int     `json:"max_age_days"`
	GraceHours  int     `json:"grace_hours"`
	Adapter     *string `json:"adapter"`
	Destination *string `json:"destination"`
	DestPath    string  `json:"dest_path"`
	AutoRotate  bool    `json:"auto_rotate"`
}

// PolicyView is a policy as the API shows it.
type PolicyView struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	System      string    `json:"system"`
	MaxAgeDays  int       `json:"max_age_days"`
	GraceHours  int       `json:"grace_hours"`
	Adapter     *string   `json:"adapter"`
	Destination *string   `json:"destination"`
	DestPath    string    `json:"dest_path"`
	AutoRotate  bool      `json:"auto_rotate"`
	Mode        string    `json:"mode"` // automatic | scheduled | manual
	CreatedBy   string    `json:"created_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var (
	kindRE       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	systemRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,39}$`)
	destPathRE   = regexp.MustCompile(`^[A-Za-z0-9/_.@=+{}-]{0,256}$`)
	placeholders = regexp.MustCompile(`\{[a-z]+\}`)
)

// Policies lists the tenant's policies.
func (s *Service) Policies(tx *store.TenantTx) ([]PolicyView, error) {
	rows, err := tx.RotationPolicies()
	if err != nil {
		return nil, err
	}
	names, err := adapterNames(tx)
	if err != nil {
		return nil, err
	}
	out := make([]PolicyView, 0, len(rows))
	for _, p := range rows {
		out = append(out, policyView(p, names))
	}
	return out, nil
}

func adapterNames(tx *store.TenantTx) (map[string]string, error) {
	rows, err := tx.RotationAdapters()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, a := range rows {
		out[a.ID] = a.Name
	}
	return out, nil
}

func nameOf(names map[string]string, id *string) *string {
	if id == nil {
		return nil
	}
	n, ok := names[*id]
	if !ok {
		return nil
	}
	return &n
}

func policyView(p *store.RotationPolicy, names map[string]string) PolicyView {
	mode := "manual"
	switch {
	case p.AdapterID != nil && p.AutoRotate:
		mode = "automatic"
	case p.AdapterID != nil:
		mode = "scheduled"
	}
	return PolicyView{ID: p.ID, Kind: p.Kind, System: p.System, MaxAgeDays: p.MaxAgeDays, GraceHours: p.GraceHours,
		Adapter: nameOf(names, p.AdapterID), Destination: nameOf(names, p.DestAdapterID), DestPath: p.DestPath,
		AutoRotate: p.AutoRotate, Mode: mode, CreatedBy: p.CreatedBy, UpdatedAt: p.UpdatedAt}
}

// PutPolicy creates the policy for a kind and system, or replaces it.
func (s *Service) PutPolicy(tx *store.TenantTx, in PolicyInput, actor string, now time.Time) (*PolicyView, bool, error) {
	if !kindRE.MatchString(in.Kind) {
		return nil, false, invalid("invalid_kind", "kind must be a secret kind such as access_key or deploy_key")
	}
	if in.System != "" && !systemRE.MatchString(in.System) {
		return nil, false, invalid("invalid_system", "system must be a system name such as aws, or empty for every system")
	}
	if in.MaxAgeDays < 1 || in.MaxAgeDays > 3650 {
		return nil, false, invalid("invalid_max_age", "max_age_days must be from 1 to 3650")
	}
	if in.GraceHours < 0 || in.GraceHours > 720 {
		return nil, false, invalid("invalid_grace", "grace_hours must be from 0 to 720")
	}
	if !destPathRE.MatchString(in.DestPath) {
		return nil, false, invalid("invalid_dest_path", "dest_path may use letters, digits and /_.@=+- and the placeholders {system}, {kind}, {name}, {account}")
	}
	for _, ph := range placeholders.FindAllString(in.DestPath, -1) {
		switch ph {
		case "{system}", "{kind}", "{name}", "{account}":
		default:
			return nil, false, invalid("invalid_dest_path", "unknown placeholder %s (use {system}, {kind}, {name}, {account})", ph)
		}
	}
	p := &store.RotationPolicy{ID: store.NewID(), TenantID: tx.Tenant(), Kind: in.Kind, System: in.System,
		MaxAgeDays: in.MaxAgeDays, GraceHours: in.GraceHours, DestPath: in.DestPath, AutoRotate: in.AutoRotate,
		CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	var adapter, dest *store.RotationAdapter
	var err error
	if in.Adapter != nil && *in.Adapter != "" {
		if adapter, err = s.adapterByName(tx, *in.Adapter, "adapter"); err != nil {
			return nil, false, err
		}
		if !Supports(adapter.Type, in.Kind) {
			return nil, false, invalid("adapter_kind_mismatch", "%s adapters cannot rotate secrets of kind %s (they rotate %s)",
				adapter.Type, in.Kind, strings.Join(kindsOf(adapter.Type), ", "))
		}
		p.AdapterID = &adapter.ID
	} else if in.AutoRotate {
		return nil, false, invalid("auto_without_adapter", "auto_rotate needs an adapter")
	}
	if in.Destination != nil && *in.Destination != "" {
		if dest, err = s.adapterByName(tx, *in.Destination, "destination"); err != nil {
			return nil, false, err
		}
		if !isDestination(dest.Type) {
			return nil, false, invalid("invalid_destination", "%s adapters cannot receive credentials; use a vault or aws_secretsmanager adapter", dest.Type)
		}
		p.DestAdapterID = &dest.ID
	}
	if adapter != nil && capsOf(adapter.Type).NeedsDestination {
		if dest == nil || in.DestPath == "" {
			return nil, false, invalid("destination_required", "%s adapters hand the new credential to a vault: set destination and dest_path", adapter.Type)
		}
	}
	if dest != nil {
		sample := expandPath(in.DestPath, Target{System: "sample", Kind: in.Kind, Name: "sample", Account: "sample"})
		if err := destOf(dest.Type).ValidatePath(sample); err != nil {
			return nil, false, invalid("invalid_dest_path", "%v", err)
		}
	}
	existing, err := tx.RotationPolicyByKey(in.Kind, in.System)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	created := errors.Is(err, store.ErrNotFound)
	if created {
		if err := tx.InsertRotationPolicy(p); err != nil {
			return nil, false, err
		}
	} else {
		p.ID, p.CreatedBy, p.CreatedAt = existing.ID, existing.CreatedBy, existing.CreatedAt
		if err := tx.UpdateRotationPolicy(p); err != nil {
			return nil, false, err
		}
	}
	action := "rotation.policy.updated"
	if created {
		action = "rotation.policy.created"
	}
	d := ojson.Object{{Key: "kind", Value: in.Kind}, {Key: "system", Value: in.System}, {Key: "max_age_days", Value: in.MaxAgeDays},
		{Key: "grace_hours", Value: in.GraceHours}, {Key: "adapter", Value: in.Adapter}, {Key: "auto_rotate", Value: in.AutoRotate}}
	if err := record(tx, now, action, "rotation_policy", p.ID, d); err != nil {
		return nil, false, err
	}
	names, err := adapterNames(tx)
	if err != nil {
		return nil, false, err
	}
	v := policyView(p, names)
	return &v, created, nil
}

func (s *Service) adapterByName(tx *store.TenantTx, name, field string) (*store.RotationAdapter, error) {
	a, err := tx.RotationAdapterByName(name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("unknown_adapter", "%s %q is not a registered rotation adapter", field, name)
	}
	return a, err
}

// DeletePolicy removes a policy.
func (s *Service) DeletePolicy(tx *store.TenantTx, id, actor string, now time.Time) error {
	p, err := tx.RotationPolicy(id)
	if errors.Is(err, store.ErrNotFound) {
		return problem(http.StatusNotFound, "not_found", "no such policy")
	}
	if err != nil {
		return err
	}
	if _, err := tx.DeleteRotationPolicy(id); err != nil {
		return err
	}
	return record(tx, now, "rotation.policy.deleted", "rotation_policy", id, ojson.Object{
		{Key: "kind", Value: p.Kind}, {Key: "system", Value: p.System}})
}

func isDestination(typ string) bool {
	switch typ {
	case TypeVault, TypeAWSSM, TypeFake:
		return true
	}
	return false
}

// capsOf and destOf use zero-value adapters: capabilities and path rules do
// not depend on a connection, so a plan needs no credentials.
func capsOf(typ string) Capabilities {
	switch typ {
	case TypeAWSIAM:
		return (&iamAdapter{}).Capabilities()
	case TypeAWSSM:
		return (&smAdapter{}).Capabilities()
	case TypeVault:
		return (&vaultAdapter{}).Capabilities()
	case TypeGitHub:
		return (&githubAdapter{}).Capabilities()
	}
	return (&fakeAdapter{}).Capabilities()
}

func validatorOf(typ string) Adapter {
	switch typ {
	case TypeAWSIAM:
		return &iamAdapter{}
	case TypeAWSSM:
		return &smAdapter{}
	case TypeVault:
		return &vaultAdapter{}
	case TypeGitHub:
		return &githubAdapter{}
	}
	return &fakeAdapter{}
}

func destOf(typ string) Destination {
	switch typ {
	case TypeVault:
		return &vaultAdapter{}
	case TypeAWSSM:
		return &smAdapter{}
	}
	return &fakeAdapter{}
}

var slugRE = regexp.MustCompile(`[^a-z0-9._-]+`)

func slug(s string) string {
	s = strings.Trim(slugRE.ReplaceAllString(strings.ToLower(s), "-"), "-.")
	if s == "" {
		return "x"
	}
	return s
}

// expandPath fills a destination path template from the secret.
func expandPath(tmpl string, t Target) string {
	return strings.NewReplacer("{system}", slug(t.System), "{kind}", slug(t.Kind), "{name}", slug(t.Name),
		"{account}", slug(t.Account)).Replace(tmpl)
}

// ---------------------------------------------------------------- plans

// Plan actions.
const (
	ActionRotate   = "rotate"    // Tessera rotates it through its adapter
	ActionManual   = "manual"    // no API or no policy: the owner has to rotate it
	ActionBlocked  = "blocked"   // a policy exists but cannot run (bad reference, missing destination)
	ActionInFlight = "in_flight" // a rotation is already running
)

// PlanItem says what a rotation of one secret would do. It is computed from
// the database alone: planning never calls a provider.
type PlanItem struct {
	SecretID    int64      `json:"secret_id"`
	Name        string     `json:"name"`
	System      string     `json:"system"`
	Kind        string     `json:"kind"`
	Account     string     `json:"account"`
	Owner       *OwnerView `json:"owner"`
	AgeDays     int        `json:"age_days"`
	MaxAgeDays  *int       `json:"max_age_days"`
	Overdue     bool       `json:"overdue"`
	Action      string     `json:"action"`
	Reason      string     `json:"reason,omitempty"`
	Adapter     *string    `json:"adapter"`
	AdapterType string     `json:"adapter_type,omitempty"`
	Destination *string    `json:"destination"`
	DestPath    string     `json:"dest_path,omitempty"`
	GraceHours  int        `json:"grace_hours"`
	Steps       []string   `json:"steps"`
	Warnings    []string   `json:"warnings"`
	JobID       *string    `json:"job_id,omitempty"`

	oldRef     string
	policy     *store.RotationPolicy
	adapterRow *store.RotationAdapter
	destRow    *store.RotationAdapter
	secret     *store.Secret
	acct       *store.Account
}

// OwnerView is an owner as the API shows it.
type OwnerView struct {
	ID     int64   `json:"id"`
	Name   string  `json:"name"`
	Email  *string `json:"email"`
	Status string  `json:"status"`
}

// snapshot is the tenant's rotation state, read once per call.
type snapshot struct {
	now      time.Time
	secrets  []*store.Secret
	accounts map[int64]*store.Account
	people   map[int64]*store.Identity
	policies []*store.RotationPolicy
	adapters map[string]*store.RotationAdapter
	active   map[int64]*store.RotationJob
	latest   map[int64]*store.RotationJob
	allowed  bool // the simulated adapter is allowed
}

func (s *Service) snapshot(tx *store.TenantTx, now time.Time) (*snapshot, error) {
	snap := &snapshot{now: now, accounts: map[int64]*store.Account{}, adapters: map[string]*store.RotationAdapter{},
		active: map[int64]*store.RotationJob{}, latest: map[int64]*store.RotationJob{}, allowed: s.AllowFake}
	var err error
	if snap.secrets, err = tx.Secrets(); err != nil {
		return nil, err
	}
	accts, err := tx.Accounts()
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		snap.accounts[a.ID] = a
	}
	if snap.people, _, err = tx.IdentityMap(); err != nil {
		return nil, err
	}
	if snap.policies, err = tx.RotationPolicies(); err != nil {
		return nil, err
	}
	ads, err := tx.RotationAdapters()
	if err != nil {
		return nil, err
	}
	for _, a := range ads {
		snap.adapters[a.ID] = a
	}
	jobs, err := tx.RotationJobs(store.RotationJobFilter{Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, j := range jobs { // newest first
		if _, seen := snap.latest[j.SecretID]; !seen {
			snap.latest[j.SecretID] = j
		}
		if inFlight(j.State) {
			snap.active[j.SecretID] = j
		}
	}
	return snap, nil
}

func inFlight(state string) bool {
	switch state {
	case store.RotOldDeleted, store.RotFailed, store.RotCancelled:
		return false
	}
	return true
}

func (snap *snapshot) policyFor(sec *store.Secret) *store.RotationPolicy {
	var any *store.RotationPolicy
	for _, p := range snap.policies {
		if p.Kind != sec.Kind {
			continue
		}
		if p.System == sec.System {
			return p
		}
		if p.System == "" {
			any = p
		}
	}
	return any
}

func (snap *snapshot) owner(acct *store.Account) (*store.Identity, *Owner) {
	if acct == nil || acct.IdentityID == nil {
		return nil, nil
	}
	who := snap.people[*acct.IdentityID]
	if who != nil && who.Type != "human" && who.OwnerID != nil {
		who = snap.people[*who.OwnerID]
	}
	if who == nil {
		return nil, nil
	}
	if who.Status != "active" {
		return who, nil // an owner who has left cannot act on a notification: it escalates
	}
	o := &Owner{IdentityID: who.ID, Name: who.Name}
	if who.Email != nil {
		o.Email = *who.Email
	}
	return who, o
}

func targetOf(sec *store.Secret, acct *store.Account, ref string) Target {
	t := Target{Kind: sec.Kind, System: sec.System, Name: sec.Name, Ref: ref}
	if acct != nil {
		t.Account = acct.Username
	}
	return t
}

// planOne decides what a rotation of sec would do.
func (s *Service) planOne(snap *snapshot, sec *store.Secret, graceOverride *int) *PlanItem {
	acct := snap.accounts[sec.AccountID]
	ref := sec.CreatedAt
	if sec.LastRotatedAt != nil {
		ref = *sec.LastRotatedAt
	}
	it := &PlanItem{SecretID: sec.ID, Name: sec.Name, System: sec.System, Kind: sec.Kind, AgeDays: timeutil.Days(snap.now, ref),
		Steps: []string{}, Warnings: []string{}, oldRef: sec.ExternalID, secret: sec, acct: acct}
	if acct != nil {
		it.Account = acct.Username
	}
	if who, _ := snap.owner(acct); who != nil {
		it.Owner = &OwnerView{ID: who.ID, Name: who.Name, Email: who.Email, Status: who.Status}
	} else {
		it.Warnings = append(it.Warnings, "the secret has no owner: notifications go to the tenant administrators")
	}
	pol := snap.policyFor(sec)
	if pol != nil {
		it.policy = pol
		max := pol.MaxAgeDays
		it.MaxAgeDays, it.Overdue = &max, it.AgeDays > max
		it.GraceHours = pol.GraceHours
	}
	if graceOverride != nil {
		it.GraceHours = *graceOverride
	}
	manual := func(reason string) *PlanItem {
		it.Action, it.Reason = ActionManual, reason
		it.Steps = []string{"Notify the owner that the secret has to be rotated by hand"}
		return it
	}
	block := func(format string, a ...any) *PlanItem {
		it.Action, it.Reason = ActionBlocked, fmt.Sprintf(format, a...)
		return it
	}
	if sec.Status != "active" {
		return block("the secret is %s, not active", sec.Status)
	}
	if j := snap.active[sec.ID]; j != nil {
		it.Action, it.JobID = ActionInFlight, &j.ID
		it.Reason = "a rotation is already " + j.State
		return it
	}
	if r := ManualReason(sec.Kind); r != "" && (pol == nil || pol.AdapterID == nil) {
		return manual(r)
	}
	if pol == nil {
		return manual("no rotation policy covers " + sec.Kind + " secrets on " + sec.System)
	}
	if pol.AdapterID == nil {
		return manual("the policy for " + sec.Kind + " has no adapter (manual rotation)")
	}
	ad := snap.adapters[*pol.AdapterID]
	if ad == nil {
		return block("the policy's adapter no longer exists")
	}
	it.adapterRow, it.Adapter, it.AdapterType = ad, &ad.Name, ad.Type
	if ad.Type == TypeFake && !snap.allowed {
		return block("the policy uses a simulated adapter, which this environment refuses")
	}
	if !Supports(ad.Type, sec.Kind) {
		return block("%s adapters cannot rotate %s secrets", ad.Type, sec.Kind)
	}
	t := targetOf(sec, acct, sec.ExternalID)
	if err := validatorOf(ad.Type).Validate(t); err != nil {
		return block("%v", err)
	}
	caps := capsOf(ad.Type)
	if caps.NeedsDestination {
		if pol.DestAdapterID == nil || pol.DestPath == "" {
			return block("the policy names no destination vault for the new credential")
		}
		dest := snap.adapters[*pol.DestAdapterID]
		if dest == nil {
			return block("the policy's destination adapter no longer exists")
		}
		if dest.Type == TypeFake && !snap.allowed {
			return block("the policy's destination is a simulated adapter, which this environment refuses")
		}
		it.destRow, it.Destination = dest, &dest.Name
		it.DestPath = expandPath(pol.DestPath, t)
		if err := destOf(dest.Type).ValidatePath(it.DestPath); err != nil {
			return block("%v", err)
		}
	}
	it.Action = ActionRotate
	it.Steps = stepsOf(it, caps)
	if !caps.CanDisable {
		it.Warnings = append(it.Warnings, "the provider cannot deactivate the old credential: it stays valid until it is deleted")
	}
	if !caps.ReportsLastUsed {
		it.Warnings = append(it.Warnings, "the provider does not report when the old credential was last used: verification covers its age only")
	}
	return it
}

func stepsOf(it *PlanItem, caps Capabilities) []string {
	steps := []string{"Create a new " + it.Kind + " through the " + it.AdapterType + " adapter"}
	if caps.NeedsDestination {
		steps = append(steps, fmt.Sprintf("Write it to %s at %s (Tessera does not keep it)", *it.Destination, it.DestPath))
	} else {
		steps = append(steps, "Confirm the new version is the one consumers read")
	}
	if it.GraceHours > 0 {
		steps = append(steps, fmt.Sprintf("Wait %d hour(s) so consumers can move to the new credential", it.GraceHours))
	}
	if caps.CanDisable {
		steps = append(steps, "Disable the old credential")
	} else {
		steps = append(steps, "Skip disabling (not supported by the provider)")
	}
	steps = append(steps, "Re-read the old credential: record its age and last use, and check nothing used it after the grace period",
		"Delete the old credential and confirm it is gone", "Notify the owner")
	return steps
}

// Plan plans a rotation of the given secrets (nil: every secret), by id.
func (s *Service) Plan(tx *store.TenantTx, secretIDs []int64, now time.Time) ([]*PlanItem, error) {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	want := map[int64]bool{}
	for _, id := range secretIDs {
		want[id] = true
	}
	var out []*PlanItem
	for _, sec := range snap.secrets {
		if len(secretIDs) > 0 && !want[sec.ID] {
			continue
		}
		out = append(out, s.planOne(snap, sec, nil))
		delete(want, sec.ID)
	}
	if len(want) > 0 {
		return nil, problem(http.StatusNotFound, "not_found", "no such secret")
	}
	return out, nil
}

// ---------------------------------------------------------------- jobs

// JobView is a job as the API shows it.
type JobView struct {
	ID           string        `json:"id"`
	SecretID     int64         `json:"secret_id"`
	Secret       string        `json:"secret"`
	System       string        `json:"system"`
	Kind         string        `json:"kind"`
	Account      string        `json:"account"`
	Origin       string        `json:"origin"`
	BulkID       *string       `json:"bulk_id"`
	Adapter      string        `json:"adapter"`
	AdapterType  string        `json:"adapter_type"`
	Destination  *string       `json:"destination"`
	DestPath     string        `json:"dest_path"`
	State        string        `json:"state"`
	FailedState  *string       `json:"failed_state"`
	OldRef       string        `json:"old_ref"`
	NewRef       *string       `json:"new_ref"`
	GraceHours   int           `json:"grace_hours"`
	Attempts     int           `json:"attempts"`
	LastError    *string       `json:"last_error"`
	NextStepAt   *time.Time    `json:"next_step_at"`
	HandedOverAt *time.Time    `json:"handed_over_at"`
	DisabledAt   *time.Time    `json:"disabled_at"`
	VerifiedAt   *time.Time    `json:"verified_at"`
	CompletedAt  *time.Time    `json:"completed_at"`
	Verification *Verification `json:"verification"`
	Steps        []JobStep     `json:"steps"`
	RequestedBy  string        `json:"requested_by"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// JobStep is one stage of the job's path, for the timeline in the UI.
type JobStep struct {
	State  string     `json:"state"`
	Status string     `json:"status"` // done | current | pending | failed | skipped
	At     *time.Time `json:"at"`
}

var jobPath = []string{store.RotCreated, store.RotHandedOver, store.RotOldDisabled, store.RotVerified, store.RotOldDeleted}

func jobRank(state string) int {
	for i, s := range jobPath {
		if s == state {
			return i + 1
		}
	}
	return 0 // pending
}

func (s *Service) jobView(snap *snapshot, names map[string]string, j *store.RotationJob) JobView {
	v := JobView{ID: j.ID, SecretID: j.SecretID, Origin: j.Origin, BulkID: j.BulkID, AdapterType: j.AdapterType,
		Destination: nameOf(names, j.DestAdapterID), DestPath: j.DestPath, State: j.State, FailedState: j.FailedState,
		OldRef: j.OldRef, NewRef: j.NewRef, GraceHours: j.GraceHours, Attempts: j.Attempts, LastError: j.LastError,
		HandedOverAt: j.HandedOverAt, DisabledAt: j.DisabledAt, VerifiedAt: j.VerifiedAt, CompletedAt: j.CompletedAt,
		RequestedBy: j.RequestedBy, CreatedAt: j.CreatedAt, UpdatedAt: j.UpdatedAt, Adapter: names[j.AdapterID]}
	if inFlight(j.State) {
		t := j.NextStepAt
		v.NextStepAt = &t
	}
	for _, sec := range snap.secrets {
		if sec.ID == j.SecretID {
			v.Secret, v.System, v.Kind = sec.Name, sec.System, sec.Kind
			if a := snap.accounts[sec.AccountID]; a != nil {
				v.Account = a.Username
			}
		}
	}
	if j.Verification != nil {
		var ver Verification
		if json.Unmarshal([]byte(*j.Verification), &ver) == nil {
			v.Verification = &ver
		}
	}
	at := map[string]*time.Time{store.RotCreated: &j.CreatedAt, store.RotHandedOver: j.HandedOverAt,
		store.RotOldDisabled: j.DisabledAt, store.RotVerified: j.VerifiedAt, store.RotOldDeleted: j.CompletedAt}
	reached := jobRank(j.State)
	if j.State == store.RotFailed && j.FailedState != nil {
		reached = jobRank(*j.FailedState)
	}
	for i, st := range jobPath {
		step, rank := JobStep{State: st, At: at[st]}, i+1
		switch {
		case j.State == store.RotOldDeleted || rank <= reached && j.State != store.RotCancelled:
			step.Status = "done"
		case rank == reached+1 && j.State == store.RotFailed:
			step.Status = "failed"
		case rank == reached+1 && j.State != store.RotCancelled:
			step.Status = "current"
		default:
			step.Status = "pending"
		}
		if st == store.RotOldDisabled && step.Status == "done" && !capsOf(j.AdapterType).CanDisable {
			step.Status = "skipped"
		}
		v.Steps = append(v.Steps, step)
	}
	return v
}

// Jobs lists jobs, newest first, optionally filtered.
func (s *Service) Jobs(tx *store.TenantTx, f store.RotationJobFilter, now time.Time) ([]JobView, error) {
	rows, err := tx.RotationJobs(f)
	if err != nil {
		return nil, err
	}
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	names, err := adapterNames(tx)
	if err != nil {
		return nil, err
	}
	out := make([]JobView, 0, len(rows))
	for _, j := range rows {
		out = append(out, s.jobView(snap, names, j))
	}
	return out, nil
}

// Job returns one job.
func (s *Service) Job(tx *store.TenantTx, id string, now time.Time) (*JobView, error) {
	j, err := tx.RotationJob(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, problem(http.StatusNotFound, "not_found", "no such rotation job")
	}
	if err != nil {
		return nil, err
	}
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	names, err := adapterNames(tx)
	if err != nil {
		return nil, err
	}
	v := s.jobView(snap, names, j)
	return &v, nil
}

// enqueue queues a job for a plan item that is ready to rotate.
func (s *Service) enqueue(tx *store.TenantTx, it *PlanItem, origin string, bulkID *string, actor string, now time.Time) (*store.RotationJob, error) {
	j := &store.RotationJob{ID: store.NewID(), TenantID: tx.Tenant(), SecretID: it.SecretID, BulkID: bulkID, Origin: origin,
		AdapterID: it.adapterRow.ID, AdapterType: it.adapterRow.Type, DestPath: it.DestPath, OldRef: it.oldRef,
		GraceHours: it.GraceHours, NextStepAt: now, RequestedBy: actor, CreatedAt: now}
	if it.destRow != nil {
		j.DestAdapterID = &it.destRow.ID
	}
	if err := tx.InsertRotationJob(j); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return nil, problem(http.StatusConflict, "in_flight", "a rotation of this secret is already running")
		}
		return nil, err
	}
	d := ojson.Object{{Key: "secret_id", Value: it.SecretID}, {Key: "secret", Value: it.Name}, {Key: "system", Value: it.System},
		{Key: "adapter", Value: it.adapterRow.Name}, {Key: "origin", Value: origin}, {Key: "grace_hours", Value: it.GraceHours}}
	if bulkID != nil {
		d = append(d, ojson.KV{Key: "bulk_id", Value: *bulkID})
	}
	return j, record(tx, now, "rotation.job.queued", "rotation_job", j.ID, d)
}

// StartRotation queues a rotation of one secret (the Rotate action). It
// refuses a secret Tessera cannot rotate (manual or blocked) with the reason.
func (s *Service) StartRotation(tx *store.TenantTx, secretID int64, actor string, now time.Time) (*JobView, error) {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	var sec *store.Secret
	for _, c := range snap.secrets {
		if c.ID == secretID {
			sec = c
		}
	}
	if sec == nil {
		return nil, problem(http.StatusNotFound, "not_found", "no such secret")
	}
	it := s.planOne(snap, sec, nil)
	switch it.Action {
	case ActionInFlight:
		return nil, problem(http.StatusConflict, "in_flight", "%s", it.Reason)
	case ActionManual:
		return nil, problem(http.StatusConflict, "manual_rotation_required", "%s", it.Reason)
	case ActionBlocked:
		return nil, problem(http.StatusConflict, "rotation_blocked", "%s", it.Reason)
	}
	j, err := s.enqueue(tx, it, store.RotOriginManual, nil, actor, now)
	if err != nil {
		return nil, err
	}
	return s.Job(tx, j.ID, now)
}

// QueueForLeaver queues the rotation of a secret a leaver had custody of (the
// JML rotate_secret step), with no grace period. It reports whether a job is
// running for the secret; false means no policy and adapter can rotate it and
// the caller keeps its old behaviour.
func (s *Service) QueueForLeaver(tx *store.TenantTx, secretID int64, actor string, now time.Time) (bool, error) {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return false, err
	}
	for _, sec := range snap.secrets {
		if sec.ID != secretID {
			continue
		}
		zero := 0
		it := s.planOne(snap, sec, &zero)
		switch it.Action {
		case ActionInFlight:
			return true, nil
		case ActionRotate:
			_, err := s.enqueue(tx, it, store.RotOriginJML, nil, actor, now)
			return err == nil, err
		}
	}
	return false, nil
}

// DueAutoRotations lists the secrets whose policy rotates them automatically
// and whose age has passed its maximum.
func (s *Service) DueAutoRotations(tx *store.TenantTx, now time.Time) ([]int64, error) {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, sec := range snap.secrets {
		pol := snap.policyFor(sec)
		if pol == nil || !pol.AutoRotate || pol.AdapterID == nil {
			continue
		}
		if it := s.planOne(snap, sec, nil); it.Action == ActionRotate && it.Overdue {
			out = append(out, sec.ID)
		}
	}
	return out, nil
}

// QueueDue queues a policy-triggered rotation of one overdue secret.
func (s *Service) QueueDue(tx *store.TenantTx, secretID int64, actor string, now time.Time) error {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return err
	}
	for _, sec := range snap.secrets {
		if sec.ID != secretID {
			continue
		}
		if it := s.planOne(snap, sec, nil); it.Action == ActionRotate && it.Overdue {
			_, err := s.enqueue(tx, it, store.RotOriginPolicy, nil, actor, now)
			var p *Problem
			if errors.As(err, &p) && p.Code == "in_flight" {
				return nil
			}
			return err
		}
	}
	return nil
}

// RetryJob puts a failed job back where it failed.
func (s *Service) RetryJob(tx *store.TenantTx, id, actor string, now time.Time) (*JobView, error) {
	j, err := tx.RotationJob(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, problem(http.StatusNotFound, "not_found", "no such rotation job")
	}
	if err != nil {
		return nil, err
	}
	if j.State != store.RotFailed {
		return nil, problem(http.StatusConflict, "not_failed", "only a failed job can be retried (this one is %s)", j.State)
	}
	to := store.RotPending
	if j.FailedState != nil {
		to = *j.FailedState
	}
	from := j.State
	j.State, j.FailedState, j.Attempts, j.NextStepAt = to, nil, 0, now
	if err := tx.UpdateRotationJob(j, from, now); err != nil {
		if errors.Is(err, store.ErrStateConflict) {
			return nil, problem(http.StatusConflict, "in_flight", "another rotation of this secret is already running")
		}
		return nil, err
	}
	if err := record(tx, now, "rotation.job.retried", "rotation_job", id, ojson.Object{{Key: "resumes_at", Value: to},
		{Key: "secret_id", Value: j.SecretID}, {Key: "requested_by", Value: actor}}); err != nil {
		return nil, err
	}
	return s.Job(tx, id, now)
}

// CancelJob cancels a job that has not created anything yet.
func (s *Service) CancelJob(tx *store.TenantTx, id, actor string, now time.Time) (*JobView, error) {
	j, err := tx.RotationJob(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, problem(http.StatusNotFound, "not_found", "no such rotation job")
	}
	if err != nil {
		return nil, err
	}
	if j.State != store.RotPending {
		return nil, problem(http.StatusConflict, "not_pending", "only a job that has not started can be cancelled (this one is %s)", j.State)
	}
	j.State = store.RotCancelled
	if err := tx.UpdateRotationJob(j, store.RotPending, now); err != nil {
		if errors.Is(err, store.ErrStateConflict) {
			return nil, problem(http.StatusConflict, "not_pending", "the job has started")
		}
		return nil, err
	}
	if err := record(tx, now, "rotation.job.cancelled", "rotation_job", id, ojson.Object{{Key: "secret_id", Value: j.SecretID},
		{Key: "requested_by", Value: actor}}); err != nil {
		return nil, err
	}
	return s.Job(tx, id, now)
}

// ---------------------------------------------------------------- overview

// SecretStatus is one secret's rotation status.
type SecretStatus struct {
	SecretID   int64      `json:"secret_id"`
	Name       string     `json:"name"`
	System     string     `json:"system"`
	Kind       string     `json:"kind"`
	Account    string     `json:"account"`
	Owner      *OwnerView `json:"owner"`
	AgeDays    int        `json:"age_days"`
	MaxAgeDays *int       `json:"max_age_days"`
	Overdue    bool       `json:"overdue"`
	Mode       string     `json:"mode"`   // automatic | scheduled | manual | none
	Action     string     `json:"action"` // what Rotate would do now
	Reason     string     `json:"reason,omitempty"`
	Adapter    *string    `json:"adapter"`
	ActiveJob  *JobLite   `json:"active_job"`
	LastJob    *JobLite   `json:"last_job"`
}

// JobLite is a job in a status row.
type JobLite struct {
	ID          string     `json:"id"`
	State       string     `json:"state"`
	Origin      string     `json:"origin"`
	At          time.Time  `json:"at"`
	CompletedAt *time.Time `json:"completed_at"`
	LastError   *string    `json:"last_error"`
}

func lite(j *store.RotationJob) *JobLite {
	if j == nil {
		return nil
	}
	return &JobLite{ID: j.ID, State: j.State, Origin: j.Origin, At: j.UpdatedAt, CompletedAt: j.CompletedAt, LastError: j.LastError}
}

// Overview lists every secret's rotation status, most overdue first.
func (s *Service) Overview(tx *store.TenantTx, now time.Time) ([]SecretStatus, error) {
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	out := make([]SecretStatus, 0, len(snap.secrets))
	for _, sec := range snap.secrets {
		if sec.Status != "active" {
			continue
		}
		it := s.planOne(snap, sec, nil)
		mode := "none"
		if p := snap.policyFor(sec); p != nil {
			mode = policyView(p, nil).Mode
		}
		if it.Action == ActionManual && mode != "none" {
			mode = "manual"
		}
		out = append(out, SecretStatus{SecretID: sec.ID, Name: sec.Name, System: sec.System, Kind: sec.Kind, Account: it.Account,
			Owner: it.Owner, AgeDays: it.AgeDays, MaxAgeDays: it.MaxAgeDays, Overdue: it.Overdue, Mode: mode, Action: it.Action,
			Reason: it.Reason, Adapter: it.Adapter, ActiveJob: lite(snap.active[sec.ID]), LastJob: lite(snap.latest[sec.ID])})
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Overdue != out[b].Overdue {
			return out[a].Overdue
		}
		return out[a].AgeDays > out[b].AgeDays
	})
	return out, nil
}

// ---------------------------------------------------------------- bulk "vendor compromised"

// BulkPlan is the dry run of a vendor-compromised rotation.
type BulkPlan struct {
	System string      `json:"system"`
	Hash   string      `json:"plan_hash"`
	Counts BulkCounts  `json:"counts"`
	Items  []*PlanItem `json:"items"`
}

// BulkCounts summarises a bulk plan.
type BulkCounts struct {
	Total    int `json:"total"`
	Rotate   int `json:"rotate"`
	Manual   int `json:"manual"`
	Blocked  int `json:"blocked"`
	InFlight int `json:"in_flight"`
}

// BulkPlanFor plans the rotation of every active secret of a system, with no
// grace period (the credentials are presumed exposed).
func (s *Service) BulkPlanFor(tx *store.TenantTx, system string, now time.Time) (*BulkPlan, error) {
	if !systemRE.MatchString(system) {
		return nil, invalid("invalid_system", "system must be a system name such as github")
	}
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	zero := 0
	p := &BulkPlan{System: system, Items: []*PlanItem{}}
	type decision struct {
		ID      int64  `json:"id"`
		Action  string `json:"action"`
		Adapter string `json:"adapter"`
		Dest    string `json:"dest"`
		Path    string `json:"path"`
		OldRef  string `json:"old_ref"`
	}
	var decisions []decision
	for _, sec := range snap.secrets {
		if sec.System != system || sec.Status != "active" {
			continue
		}
		it := s.planOne(snap, sec, &zero)
		p.Items = append(p.Items, it)
		d := decision{ID: sec.ID, Action: it.Action, Path: it.DestPath, OldRef: sec.ExternalID}
		if it.Adapter != nil {
			d.Adapter = *it.Adapter
		}
		if it.Destination != nil {
			d.Dest = *it.Destination
		}
		decisions = append(decisions, d)
		p.Counts.Total++
		switch it.Action {
		case ActionRotate:
			p.Counts.Rotate++
		case ActionManual:
			p.Counts.Manual++
		case ActionBlocked:
			p.Counts.Blocked++
		case ActionInFlight:
			p.Counts.InFlight++
		}
	}
	if p.Counts.Total == 0 {
		return nil, problem(http.StatusNotFound, "no_secrets", "no active secrets are recorded for %q", system)
	}
	raw, err := json.Marshal(decisions)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(system+"\n"), raw...))
	p.Hash = hex.EncodeToString(sum[:])
	return p, nil
}

// BulkInput confirms a bulk run: the plan hash the caller was shown, and why.
type BulkInput struct {
	System   string `json:"system"`
	Reason   string `json:"reason"`
	PlanHash string `json:"plan_hash"`
}

// BulkView is a recorded bulk run.
type BulkView struct {
	ID          string          `json:"id"`
	System      string          `json:"system"`
	Reason      string          `json:"reason"`
	PlanHash    string          `json:"plan_hash"`
	RequestedBy string          `json:"requested_by"`
	CreatedAt   time.Time       `json:"created_at"`
	Counts      BulkCounts      `json:"counts"`
	Items       []BulkItem      `json:"items"`
	Jobs        []JobView       `json:"jobs"`
	Progress    map[string]int  `json:"progress"`
	Raw         json.RawMessage `json:"-"`
}

// BulkItem is what the confirmed plan decided for one secret.
type BulkItem struct {
	SecretID int64   `json:"secret_id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Action   string  `json:"action"`
	Reason   string  `json:"reason,omitempty"`
	Adapter  *string `json:"adapter"`
	Owner    *string `json:"owner"`
}

// ExecuteBulk runs a confirmed bulk plan: it re-plans, refuses if the plan
// changed since it was shown, queues a job for every secret that can be
// rotated and tells the owner of every secret, including those that need
// manual rotation.
func (s *Service) ExecuteBulk(tx *store.TenantTx, in BulkInput, actor string, now time.Time) (*BulkView, error) {
	if len(strings.TrimSpace(in.Reason)) < 10 {
		return nil, invalid("reason_required", "reason must say why (at least 10 characters)")
	}
	plan, err := s.BulkPlanFor(tx, in.System, now)
	if err != nil {
		return nil, err
	}
	if in.PlanHash != plan.Hash {
		return nil, problem(http.StatusConflict, "plan_changed", "the credentials of %s changed since the plan was made; review the new plan", in.System)
	}
	items := make([]BulkItem, 0, len(plan.Items))
	for _, it := range plan.Items {
		bi := BulkItem{SecretID: it.SecretID, Name: it.Name, Kind: it.Kind, Action: it.Action, Reason: it.Reason, Adapter: it.Adapter}
		if it.Owner != nil {
			n := it.Owner.Name
			bi.Owner = &n
		}
		items = append(items, bi)
	}
	raw, err := json.Marshal(map[string]any{"counts": plan.Counts, "items": items})
	if err != nil {
		return nil, err
	}
	b := &store.RotationBulk{ID: store.NewID(), TenantID: tx.Tenant(), System: in.System, Reason: strings.TrimSpace(in.Reason),
		Plan: string(raw), PlanHash: plan.Hash, RequestedBy: actor, CreatedAt: now}
	if err := tx.InsertRotationBulk(b); err != nil {
		return nil, err
	}
	snap, err := s.snapshot(tx, now)
	if err != nil {
		return nil, err
	}
	for _, it := range plan.Items {
		n := Notification{SecretID: it.SecretID, SecretName: it.Name, System: it.System, Kind: it.Kind, BulkID: b.ID,
			Event: EventVendorCompromise}
		_, n.Owner = snap.owner(it.acct)
		var jobID string
		switch it.Action {
		case ActionRotate:
			j, err := s.enqueue(tx, it, store.RotOriginVendor, &b.ID, actor, now)
			if err != nil {
				return nil, err
			}
			jobID = j.ID
			n.Subject = fmt.Sprintf("%s was reported compromised: %s is being rotated", in.System, it.Name)
			n.Body = "Tessera queued an immediate rotation (no grace period). Update anything that still reads the old credential."
		case ActionInFlight:
			n.Subject = fmt.Sprintf("%s was reported compromised: a rotation of %s is already running", in.System, it.Name)
			n.Body = "The rotation already in progress continues."
		default:
			n.Event = EventManualRequired
			n.Subject = fmt.Sprintf("%s was reported compromised: rotate %s by hand", in.System, it.Name)
			n.Body = it.Reason
		}
		n.JobID = jobID
		if err := s.notify(tx, n); err != nil {
			return nil, err
		}
	}
	if err := record(tx, now, "rotation.bulk.executed", "rotation_bulk", b.ID, ojson.Object{{Key: "system", Value: in.System},
		{Key: "reason", Value: b.Reason}, {Key: "plan_hash", Value: plan.Hash}, {Key: "total", Value: plan.Counts.Total},
		{Key: "rotate", Value: plan.Counts.Rotate}, {Key: "manual", Value: plan.Counts.Manual},
		{Key: "blocked", Value: plan.Counts.Blocked}, {Key: "in_flight", Value: plan.Counts.InFlight}}); err != nil {
		return nil, err
	}
	return s.Bulk(tx, b.ID, now)
}

// Bulks lists the recorded bulk runs, newest first, with their progress.
func (s *Service) Bulks(tx *store.TenantTx, now time.Time) ([]BulkView, error) {
	rows, err := tx.RotationBulks()
	if err != nil {
		return nil, err
	}
	out := make([]BulkView, 0, len(rows))
	for _, b := range rows {
		v, err := s.bulkView(tx, b, now, false)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, nil
}

// Bulk returns one bulk run with its jobs.
func (s *Service) Bulk(tx *store.TenantTx, id string, now time.Time) (*BulkView, error) {
	b, err := tx.RotationBulk(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, problem(http.StatusNotFound, "not_found", "no such bulk rotation")
	}
	if err != nil {
		return nil, err
	}
	return s.bulkView(tx, b, now, true)
}

func (s *Service) bulkView(tx *store.TenantTx, b *store.RotationBulk, now time.Time, withJobs bool) (*BulkView, error) {
	v := &BulkView{ID: b.ID, System: b.System, Reason: b.Reason, PlanHash: b.PlanHash, RequestedBy: b.RequestedBy,
		CreatedAt: b.CreatedAt, Items: []BulkItem{}, Jobs: []JobView{}, Progress: map[string]int{}}
	var stored struct {
		Counts BulkCounts `json:"counts"`
		Items  []BulkItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(b.Plan), &stored); err == nil {
		v.Counts, v.Items = stored.Counts, stored.Items
	}
	jobs, err := tx.RotationJobs(store.RotationJobFilter{BulkID: b.ID, Limit: 5000})
	if err != nil {
		return nil, err
	}
	for _, j := range jobs {
		v.Progress[j.State]++
	}
	if withJobs {
		if v.Jobs, err = s.Jobs(tx, store.RotationJobFilter{BulkID: b.ID, Limit: 5000}, now); err != nil {
			return nil, err
		}
	}
	return v, nil
}
