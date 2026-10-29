package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// JIT re-request in the revoke window and the calibration it feeds (issue #663, LP-7; design sections 9 to 11).
// A JIT request for a grant the loop revoked, before the revocation is final, labels the revocation a false
// positive. The access itself is the ordinary time-bound JIT grant: the standing grant stays revoked.

func (s *Server) registerLPJITRoutes() {
	s.handle(http.MethodGet, "/api/lp/calibration", read, need(auth.PermGraphRead), s.rd(s.lpCalibration))
}

// lpOnJITRequest runs in the transaction of the JIT request that was just filed. The requester's accounts are the
// principals the loop may have revoked from (an AWS account's external id is its ARN) and the requested group's
// external id is the policy that was revoked; nothing matches for a request that has no such revocation.
func (s *Server) lpOnJITRequest(c *store.TenantTx, rq *store.AccessRequest) error {
	g, err := c.Group(rq.GroupID)
	if err != nil {
		return err
	}
	if g.ExternalID == "" {
		return nil
	}
	ident, err := c.Identity(rq.IdentityID)
	if err != nil {
		return err
	}
	accts, err := c.IdentityAccounts(rq.IdentityID)
	if err != nil {
		return err
	}
	principals := make([]string, 0, len(accts))
	for _, a := range accts {
		principals = append(principals, a.ExternalID)
	}
	_, err = lp.OnJITRequest(c, s.clock(), lp.JITRequest{RequestID: rq.ID, Requester: ident.Name, Principals: principals, Group: g.ExternalID})
	return err
}

// lpCalibration answers restores plus JIT re-requests divided by revocations, per confidence level, over 60 days.
func (s *Server) lpCalibration(r *http.Request, _ *params) (int, any, error) {
	levels, err := lp.Calibration(store.TxFrom(r.Context()), s.clock())
	if err != nil {
		return 0, nil, err
	}
	return http.StatusOK, map[string]any{"window_days": lp.CalibrationDays, "high_threshold_percent": lp.HighFalsePositivePercent,
		"levels": levels}, nil
}
