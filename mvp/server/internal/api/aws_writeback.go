package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/leastpriv"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The AWS write target's manual path (issue #660, LP-4; design least-privilege-loop §4.1, §5, §6.3): a person applies
// a verified right-size of one policy, and can put it back. There is no auto mode here (LP-5, LP-8).
//
//	POST /api/aws/principals/{arn}/right-size/apply
//	  {"policy_arn": "...", "unused_days": 60, "candidate_sha256": "<document_sha256 of the right-size answer>"}
//	POST /api/aws/changes/{op_id}/restore
//
// Nothing is written by the request itself: it queues a provisioning operation on the tenant's aws target, which the
// engine sends with the writer role and verifies with the reader role (a mismatch is a failed step with a finding
// and an audit event). The target must have write-back on, and turning that on takes a second admin (#569). The
// right-size is computed again at the request, and the digest the reviewer saw must be the digest of what is
// applied, so a snapshot that moved under the reviewer is refused rather than applied.

func (s *Server) registerAWSWriteRoutes() {
	s.handle(http.MethodPost, "/api/aws/principals/{arn}/right-size/apply", write, needStepUp(auth.PermProvisioningManage, auth.StepUpPolicy), s.rd(s.awsRightSizeApply))
	s.handle(http.MethodPost, "/api/aws/changes/{op_id}/restore", write, needStepUp(auth.PermProvisioningManage, auth.StepUpPolicy), s.rd(s.awsRestore))
}

type awsApplyIn struct {
	awsRightSizeIn
	// CandidateSHA256 is the document_sha256 of the right-size the person reviewed.
	CandidateSHA256 string `json:"candidate_sha256"`
}

func writeErr(status int, code, msg string) error {
	return &readiness.Error{Status: status, Code: code, Msg: msg}
}

// awsTarget finds the aws target that writes through a connector.
func awsTarget(tx *store.TenantTx, connectorID string) (*store.ProvTarget, error) {
	ts, err := tx.ProvTargets()
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		var st provision.Settings
		if t.Kind == provision.KindAWS && json.Unmarshal([]byte(t.Settings), &st) == nil && st.AWS != nil && st.AWS.ConnectorID == connectorID {
			return t, nil
		}
	}
	return nil, writeErr(http.StatusConflict, "no_aws_target", "no AWS write target is configured for the connector that collected this snapshot (Admin > Provisioning)")
}

func (s *Server) awsRightSizeApply(r *http.Request, p *params) (int, any, error) {
	arn, err := awsName("principal", p.path["arn"], true)
	if err != nil {
		return 0, nil, err
	}
	var in awsApplyIn
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	if err := in.check(); err != nil {
		return 0, nil, err
	}
	if raw, err := hex.DecodeString(in.CandidateSHA256); err != nil || len(raw) != 32 {
		return 0, nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "invalid_candidate_sha256",
			Msg: "candidate_sha256 is required: the document_sha256 of the right-size you reviewed"}
	}
	res, err := s.rightSize(r, arn, in.awsRightSizeIn)
	if err != nil {
		return 0, nil, err
	}
	v := res.view
	switch {
	case v.Verdict != leastpriv.VerdictVerified:
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "right_size_not_verified", "only a verified right-size is applied: "+strings.Join(v.Reasons, "; "))
	case !v.Exclusive:
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "policy_is_shared", "the policy is attached to other principals too: right-sizing a shared policy is a suggestion only")
	case v.Confidence.Level != leastpriv.ConfHigh && v.Confidence.Level != leastpriv.ConfMedium:
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "confidence_too_low", "the evidence for the removed permissions is rated "+string(v.Confidence.Level)+": only high or medium is acted on")
	case res.doc == nil || res.doc.VersionID == "" || len(res.doc.RawJSON) == 0:
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "policy_version_unknown", "the snapshot has no default version of the policy: collect again")
	}
	tx, now := store.TxFrom(r.Context()), s.clock()
	t, err := awsTarget(tx, v.Connector)
	if err != nil {
		return 0, nil, err
	}
	if !t.WriteBack {
		return 0, nil, writeErr(http.StatusConflict, "write_back_off", "write-back is off on the AWS target: a different admin must approve enabling it (change request provisioning.write_back.enable)")
	}
	if v.DocumentSHA256 != in.CandidateSHA256 {
		return 0, nil, writeErr(http.StatusConflict, "stale_candidate", "the right-size changed since it was reviewed (snapshot or usage moved): review it again")
	}
	prior := string(res.doc.RawJSON)
	chg := &target.AWSChange{PolicyARN: in.PolicyARN, Document: v.Document, Prior: prior, PriorSHA256: target.DocDigest(prior), PriorVersionID: res.doc.VersionID}
	key := "aws:rightsize:" + seal.SHA256Hex([]byte(arn+"\x00"+in.PolicyARN+"\x00"+res.doc.VersionID+"\x00"+v.DocumentSHA256))
	op, err := provision.Enqueue(tx, now, t.ConnectionID, provision.Change{Kind: target.AWSSetPolicyVersion, Account: target.Account{Username: arn},
		AWS: chg, Source: provision.SourceLeastPriv, Key: key})
	if err != nil {
		return 0, nil, provErr(err)
	}
	if err := tx.Audit(now, actor(r), "aws.right_size.requested", ojson.Object{{Key: "op_id", Value: op.ID}, {Key: "principal", Value: arn},
		{Key: "policy_arn", Value: in.PolicyARN}, {Key: "candidate_sha256", Value: v.DocumentSHA256}, {Key: "prior_version_id", Value: res.doc.VersionID},
		{Key: "connection_id", Value: t.ConnectionID}}); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, awsChangeView{OpID: op.ID, Status: op.Status, Kind: op.Kind, Principal: arn, PolicyARN: in.PolicyARN,
		CandidateSHA256: v.DocumentSHA256, PriorVersionID: res.doc.VersionID}, nil
}

type awsChangeView struct {
	OpID            string `json:"op_id"`
	Status          string `json:"status"`
	Kind            string `json:"kind"`
	Principal       string `json:"principal"`
	PolicyARN       string `json:"policy_arn,omitempty"`
	CandidateSHA256 string `json:"candidate_sha256,omitempty"`
	PriorVersionID  string `json:"prior_version_id,omitempty"`
	RestoreOf       string `json:"restore_of,omitempty"`
}

// awsRestore queues the restore of a verified AWS change: the state recorded at the revoke, put back exactly. The
// operation it undoes must be this tenant's, an AWS revoke, sent by the least-privilege path and verified; a restore
// that is already queued or done is returned as it is. A restore is not blocked by write-back being off: it only
// returns what a verified change took, with the digest recorded then.
func (s *Server) awsRestore(r *http.Request, p *params) (int, any, error) {
	id := p.path["op_id"]
	if !idRE.MatchString(id) {
		return 0, nil, badRequest("invalid_op", "op_id must be an operation id")
	}
	if err := decodeBody(r, &struct{}{}, true); err != nil {
		return 0, nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock()
	op, err := tx.ProvOp(id)
	if errors.Is(err, store.ErrNotFound) {
		return 0, nil, notFoundErr("operation")
	} else if err != nil {
		return 0, nil, err
	}
	kind := target.AWSRestoreKind(op.Kind)
	switch {
	case kind == "":
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "not_restorable", "only an AWS change that took access away can be restored")
	case op.Source != provision.SourceLeastPriv:
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "not_restorable", "only a least-privilege change can be restored here")
	case op.Status != provision.Verified:
		return 0, nil, writeErr(http.StatusConflict, "not_verified", "only a verified change can be restored (this one is "+op.Status+"): a change that did not verify is retried or cancelled")
	}
	req, err := provision.Request(op)
	if err != nil || req.AWS == nil {
		return 0, nil, writeErr(http.StatusUnprocessableEntity, "not_restorable", "the operation has no recorded prior state")
	}
	chg := *req.AWS
	chg.RestoreOf = op.ID
	if kind == target.AWSPutInlinePolicy {
		chg.Document = chg.Prior // exactly the state recorded at the revoke; the target checks it against the digest
	}
	rop, err := provision.Enqueue(tx, now, op.ConnectionID, provision.Change{Kind: kind, Account: req.Account, AWS: &chg,
		Source: provision.SourceLeastPriv, Key: "aws:restore:" + op.ID})
	if err != nil {
		return 0, nil, provErr(err)
	}
	if err := tx.Audit(now, actor(r), "aws.change.restore_requested", ojson.Object{{Key: "op_id", Value: rop.ID}, {Key: "restore_of", Value: op.ID},
		{Key: "kind", Value: rop.Kind}, {Key: "principal", Value: req.Account.Username}}); err != nil {
		return 0, nil, err
	}
	return http.StatusAccepted, awsChangeView{OpID: rop.ID, Status: rop.Status, Kind: rop.Kind, Principal: req.Account.Username,
		PolicyARN: chg.PolicyARN, RestoreOf: op.ID}, nil
}
