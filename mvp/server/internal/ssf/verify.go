package ssf

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// ErrNoVerification: the transmitter has no verification endpoint.
var ErrNoVerification = &ConfigError{"this transmitter has no verification endpoint: set verification_url, or discover it"}

// RequestVerification asks the transmitter to send a verification event
// (SSF 1.0 section 8.1.4.2): it POSTs a random state to the verification
// endpoint, and records the state. The event itself arrives like any other
// SET; the transmitter is verified when its state comes back. The endpoint is
// called with the transmitter's API token (or, for a poll stream, its poll
// token).
func (s *Service) RequestVerification(ctx context.Context, db *store.DB, tenant tenancy.ID, id, actor string) error {
	var tr *store.SSFTransmitter
	var token string
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) error {
		var err error
		if tr, err = c.SSFTransmitter(id); errors.Is(err, store.ErrNotFound) {
			return ErrNoSuchTransmitter
		} else if err != nil {
			return err
		}
		if token, err = s.open(tenant, tr.ID, "api_token_enc", tr.APITokenEnc); err != nil {
			return err
		}
		if token == "" && tr.Delivery == store.SSFPoll {
			token, err = s.open(tenant, tr.ID, "secret_enc", tr.SecretEnc)
		}
		return err
	}); err != nil {
		return err
	}
	if tr.VerificationURL == "" {
		return ErrNoVerification
	}
	state := seal.RandomSecret(16)
	status, _, err := s.do(ctx, http.MethodPost, tr.VerificationURL, token, map[string]string{"state": state}, 1<<20)
	if err == nil && status != http.StatusOK && status != http.StatusNoContent && status != http.StatusAccepted {
		err = fmt.Errorf("the verification endpoint answered %d", status)
	}
	if err != nil {
		s.noteError(ctx, db, tenant, tr.ID, "verification request failed: "+err.Error())
		return &ConfigError{"the verification request failed: " + err.Error()}
	}
	return db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		now := s.now()
		if err := c.SetSSFVerificationRequested(tr.ID, state, now); err != nil {
			return err
		}
		return c.Audit(now, actor, "ssf.verification_requested", ojson.Object{{Key: "transmitter_id", Value: tr.ID},
			{Key: "transmitter", Value: tr.Name}})
	})
}
