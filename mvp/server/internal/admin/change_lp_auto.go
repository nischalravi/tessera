package admin

import (
	"errors"
	"fmt"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/lpauto"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policybundle"
	"github.com/nischalravi/tessera/mvp/server/internal/rolesascode"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// TypeLPAutoPolicyApply applies the automatic least-privilege policy (lp/auto.yaml) of the access-as-code repository
// (issue #664, LP-8; design docs/design/least-privilege-loop.md sections 3 and 11, following the AC-4 apply of
// change_roles_bundle.go). Two people always: the requester files the files with the digest of the policy they
// reviewed, a different admin approves what the payload hash says, and the applier parses the files again in its
// own transaction and refuses a policy that is not the approved one (409 stale_plan). Applying a policy does not
// turn auto mode on: that is a lp.settings.update to mode auto (two people again), which needs a policy to exist.
const TypeLPAutoPolicyApply = "lp.auto_policy.apply"

type lpAutoPayload struct {
	Commit       string            `json:"commit"`
	Files        map[string]string `json:"files"`
	BundleSHA256 string            `json:"bundle_sha256"`
	PolicySHA256 string            `json:"policy_sha256"`
}

func (v *lpAutoPayload) bundle() policybundle.Files {
	f := make(policybundle.Files, len(v.Files))
	for p, s := range v.Files {
		f[p] = []byte(s)
	}
	return f
}

// LPAutoParse reads and validates the policy of a bundle: the one place both the API and the change type do it.
func LPAutoParse(files policybundle.Files) (*lpauto.Policy, error) {
	if len(files) == 0 || len(files) > policybundle.MaxFiles {
		return nil, invalid("files is 1 to %d files", policybundle.MaxFiles)
	}
	total := 0
	for _, b := range files {
		total += len(b)
	}
	if total > policybundle.MaxBytes {
		return nil, invalid("files is at most %d bytes", policybundle.MaxBytes)
	}
	data, ok := files[lpauto.File]
	if !ok {
		return nil, invalid("files has no %s", lpauto.File)
	}
	p, err := lpauto.Parse(data)
	var le *lpauto.Error
	if errors.As(err, &le) {
		return nil, newErr(422, "invalid_auto_policy", "%s", le.Msg)
	}
	return p, err
}

func init() {
	changeTypes[TypeLPAutoPolicyApply] = typed(TypeLPAutoPolicyApply, nil, planLPAuto, applyLPAuto,
		func(_ *env, v *lpAutoPayload) string {
			return fmt.Sprintf("Apply the automatic least-privilege policy of policy repository commit %s (policy %.12s)", v.Commit, v.PolicySHA256)
		})
}

// planLPAuto files a request only for a policy that is valid and is the one named now: what the requester reviewed.
func planLPAuto(_ *env, v *lpAutoPayload) (plan, error) {
	if blankCommit(v.Commit) || len(v.Commit) > lpauto.MaxCommit {
		return plan{}, invalid("commit is 1 to %d characters", lpauto.MaxCommit)
	}
	files := v.bundle()
	if d := rolesascode.Digest(files); d != v.BundleSHA256 {
		return plan{}, invalid("bundle_sha256 is %q; the files hash to %s", v.BundleSHA256, d)
	}
	p, err := LPAutoParse(files)
	if err != nil {
		return plan{}, err
	}
	if d := p.Digest(); d != v.PolicySHA256 {
		return plan{}, conflict("stale_plan", "the policy is %s, not %s; read it again", d, v.PolicySHA256)
	}
	return plan{twoPerson: true, target: "lp"}, nil
}

func applyLPAuto(e *env, ch *store.AdminChange, v *lpAutoPayload) error {
	p, err := LPAutoParse(v.bundle())
	if err != nil {
		return err
	}
	if d := p.Digest(); d != v.PolicySHA256 {
		return conflict("stale_plan", "the policy is %s, not %s", d, v.PolicySHA256)
	}
	by, approver := ch.RequestedBy.String(), ""
	if ch.ApprovedBy != nil {
		by, approver = ch.ApprovedBy.String(), ch.ApprovedBy.String()
	}
	row := &store.LPAutoPolicy{Policy: p.Canonical(), PolicySHA256: v.PolicySHA256, Commit: v.Commit, AppliedBy: ch.RequestedBy.String(), ApprovedBy: approver}
	if err := e.tx.PutLPAutoPolicy(row, e.now); err != nil {
		return err
	}
	detail := ojson.Object{{Key: "change_id", Value: ch.ID.String()}, {Key: "requested_by", Value: ch.RequestedBy.String()},
		{Key: "commit", Value: v.Commit}, {Key: "bundle_sha256", Value: v.BundleSHA256}, {Key: "policy_sha256", Value: v.PolicySHA256},
		{Key: "policy", Value: p.Canonical()}, {Key: "applied_by", Value: by}}
	if approver != "" {
		detail = append(detail, ojson.KV{Key: "approved_by", Value: approver})
	}
	_, err = audit.Record(e.tx.Context(), e.tx, "lp.auto_policy_applied", detail, audit.At(e.now), audit.Target("admin_change", ch.ID.String()))
	return err
}
