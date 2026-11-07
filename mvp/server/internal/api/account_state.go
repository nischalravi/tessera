package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Account disable and enable in a target system (issue #915).
//
//	POST /api/accounts/{account_id}/disable   {reason}
//	POST /api/accounts/{account_id}/enable    {reason}
//	POST /api/accounts/disable                {ids, reason}   at most 100; answers per id
//	POST /api/accounts/enable                 {ids, reason}
//
// Neither edits the account. Each queues a provisioning operation (the connection's write path, source "api")
// whose completion sets the account's status in Tessera once the engine's re-read of the target confirms it; a
// re-read that does not agree raises a finding and the account keeps its status. Until then the account list
// shows "pending": "disable" or "enable". An account whose system has no connection with write-back on answers
// 409 target_read_only (per id in the bulk form), and Enable also needs a connector that can set an account active
// (provision.SupportsEnable). They need identities.contain and step-up, like Disable of an identity.

// maxAccountStateIDs bounds the bulk form.
const maxAccountStateIDs = 100

// accountStateKeyPrefix starts the idempotency key of every operation made here: "account-state:<id>:<disable|enable>:<n>".
const accountStateKeyPrefix = "account-state:"

func (s *Server) registerAccountStateRoutes() {
	contain := needStepUp(auth.PermIdentitiesContain, auth.StepUpPolicy)
	s.handle(http.MethodPost, "/api/accounts/disable", write, contain, s.disableAccounts)
	s.handle(http.MethodPost, "/api/accounts/enable", write, contain, s.enableAccounts)
	s.handle(http.MethodPost, "/api/accounts/{account_id}/disable", write, contain, s.disableAccount)
	s.handle(http.MethodPost, "/api/accounts/{account_id}/enable", write, contain, s.enableAccount)
}

// accountStateResult is the outcome for one account.
type accountStateResult struct {
	ID     int64  `json:"id"`
	Status string `json:"status"` // queued | pending | held | error
	OpID   string `json:"op_id,omitempty"`
	Error  string `json:"error,omitempty"`
	Detail string `json:"detail,omitempty"`
	code   int    // HTTP status of the error, for the single form
}

func (s *Server) disableAccount(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.accountStateOne(r, p, false)
}
func (s *Server) enableAccount(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.accountStateOne(r, p, true)
}
func (s *Server) disableAccounts(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.accountStateBulk(r, p, false)
}
func (s *Server) enableAccounts(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	return s.accountStateBulk(r, p, true)
}

func (s *Server) accountStateOne(r *http.Request, p *params, enable bool) (any, error) {
	var b struct {
		Reason string `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id := p.pathInt("account_id")
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	res, err := s.accountState(r, []int64{id}, strings.TrimSpace(b.Reason), enable)
	if err != nil {
		return nil, err
	}
	if x := res[0]; x.Status == "error" {
		if x.code == http.StatusNotFound {
			return nil, errStatus(http.StatusNotFound, "account not found")
		}
		return nil, &readiness.Error{Status: x.code, Code: x.Error, Msg: x.Detail}
	}
	return statusBody{http.StatusAccepted, res[0]}, nil
}

func (s *Server) accountStateBulk(r *http.Request, _ *params, enable bool) (any, error) {
	var b struct {
		IDs    []int64 `json:"ids"`
		Reason string  `json:"reason"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	if len(b.IDs) == 0 || len(b.IDs) > maxAccountStateIDs {
		return nil, badRequest("invalid_ids", "ids: 1 to "+strconv.Itoa(maxAccountStateIDs)+" account ids")
	}
	seen := map[int64]bool{}
	for _, id := range b.IDs {
		if id <= 0 || seen[id] {
			return nil, badRequest("invalid_ids", "ids must be positive and listed once")
		}
		seen[id] = true
	}
	if err := checkReason(b.Reason); err != nil {
		return nil, err
	}
	res, err := s.accountState(r, b.IDs, strings.TrimSpace(b.Reason), enable)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, x := range res {
		if x.Status != "error" {
			n++
		}
	}
	return ojson.Object{{Key: "results", Value: res}, {Key: "accepted", Value: n}, {Key: "failed", Value: len(res) - n}}, nil
}

// accountState queues the operation for each account inside the request's transaction and audits every id, a
// refusal included, so the ledger shows what was asked.
func (s *Server) accountState(r *http.Request, ids []int64, reason string, enable bool) ([]accountStateResult, error) {
	c := store.TxFrom(r.Context())
	now := s.clock()
	verb, event, want := "disable", "account.disable_requested", "active"
	if enable {
		verb, event, want = "enable", "account.enable_requested", "disabled"
	}
	inflight, err := c.InFlightProvOpsByKeyPrefix(accountStateKeyPrefix)
	if err != nil {
		return nil, err
	}
	pending := map[int64]string{} // account id -> direction in flight
	pendingOp := map[int64]string{}
	for _, op := range inflight {
		if id, dir, ok := parseAccountStateKey(op.IdempotencyKey); ok {
			pending[id], pendingOp[id] = dir, op.ID
		}
	}
	out := make([]accountStateResult, 0, len(ids))
	for _, id := range ids {
		res, err := s.accountStateFor(c, now, r, id, reason, verb, want, enable, pending, pendingOp)
		if err != nil {
			return nil, err
		}
		fields := ojson.Object{{Key: "account_id", Value: id}, {Key: "reason", Value: reason}, {Key: "result", Value: res.Status}}
		if res.OpID != "" {
			fields = append(fields, ojson.KV{Key: "op_id", Value: res.OpID})
		}
		if res.Error != "" {
			fields = append(fields, ojson.KV{Key: "error", Value: res.Error})
		}
		if err := c.Audit(now, actor(r), event, fields); err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func refuse(id int64, code int, errCode, detail string) accountStateResult {
	return accountStateResult{ID: id, Status: "error", Error: errCode, Detail: detail, code: code}
}

func (s *Server) accountStateFor(c *store.TenantTx, now time.Time, r *http.Request, id int64, reason, verb, want string, enable bool,
	pending map[int64]string, pendingOp map[int64]string) (accountStateResult, error) {
	a, err := c.Account(id)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(id, http.StatusNotFound, "not_found", "account not found"), nil
	}
	if err != nil {
		return accountStateResult{}, err
	}
	if dir, ok := pending[id]; ok {
		if (dir == "enable") == enable {
			return accountStateResult{ID: id, Status: "pending", OpID: pendingOp[id]}, nil
		}
		return refuse(id, http.StatusConflict, "operation_in_flight", "an account "+dir+" is already waiting for the target"), nil
	}
	if a.Status != want {
		return refuse(id, http.StatusConflict, "invalid_state", "only a"+map[bool]string{false: "n active", true: " disabled"}[enable]+
			" account can be "+verb+"d (it is "+a.Status+")"), nil
	}
	t, err := provision.Route(c, a.System)
	if err != nil {
		return accountStateResult{}, err
	}
	if t == nil {
		return refuse(id, http.StatusConflict, "target_read_only",
			a.System+" has no connection with write-back on, so Tessera cannot "+verb+" the account there"), nil
	}
	ch := provision.Change{System: a.System, Source: provision.SourceAPI,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID},
		Key:     accountStateKeyPrefix + strconv.FormatInt(id, 10) + ":" + verb + ":" + store.NewID(),
		Data:    provision.AccountData{AccountID: id}}
	if enable {
		if !provision.SupportsEnable(t.Kind) {
			return refuse(id, http.StatusConflict, "target_read_only", "the "+t.Kind+" connector cannot set an account active again"), nil
		}
		ch.Kind, ch.Completion = target.UpdateAccount, provision.CompleteAccountEnable
		ch.Account.Attrs = map[string]string{"active": "true"}
	} else {
		ch.Kind, ch.Completion = target.DisableAccount, provision.CompleteAccountDisable
	}
	op, err := provision.Enqueue(c, now, t.ConnectionID, ch)
	if err != nil {
		var pe *provision.Error
		if errors.As(err, &pe) {
			return refuse(id, pe.Status, pe.Code, pe.Msg), nil
		}
		return accountStateResult{}, err
	}
	if op.Status == provision.Held {
		return accountStateResult{ID: id, Status: "held"}, nil
	}
	return accountStateResult{ID: id, Status: "queued", OpID: op.ID}, nil
}

// parseAccountStateKey reads "account-state:<id>:<direction>:<n>".
func parseAccountStateKey(k string) (id int64, dir string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(k, accountStateKeyPrefix), ":")
	if len(parts) != 3 || (parts[1] != "disable" && parts[1] != "enable") {
		return 0, "", false
	}
	n, err := strconv.ParseInt(parts[0], 10, 64)
	return n, parts[1], err == nil
}

// pendingAccountStates maps an account id to the direction ("disable" or "enable") of its operation in flight.
func pendingAccountStates(c *store.TenantTx) (map[int64]string, error) {
	ops, err := c.InFlightProvOpsByKeyPrefix(accountStateKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := map[int64]string{}
	for _, op := range ops {
		if id, dir, ok := parseAccountStateKey(op.IdempotencyKey); ok {
			out[id] = dir
		}
	}
	return out, nil
}
