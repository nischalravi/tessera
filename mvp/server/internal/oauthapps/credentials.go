package oauthapps

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Containment of a credential added to an app (issue #474): remove the secret
// at the provider, re-read to verify, and audit. Revoking a permission that
// was added is the revoke of #107 (RevokeGrant); this is the same flow for a
// secret or certificate.

// OutcomeRemoved is the outcome of a credential the provider confirmed gone.
const OutcomeRemoved = "removed"

// ErrNoCredential: the credential is not an active secret or certificate of the app.
var ErrNoCredential = errors.New("oauthapps: no such credential on the app")

// CredentialReport is the result of removing one credential.
type CredentialReport struct {
	AppID   string `json:"app_id"`
	App     string `json:"app"`
	FactID  string `json:"credential_id"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
	Outcome string `json:"outcome"` // removed, failed, manual
	Detail  string `json:"detail,omitempty"`
	OK      bool   `json:"ok"`
}

// RemoveCredential removes one credential of an app at the provider. It never
// holds a transaction during a provider call: a short transaction audits
// oauthapps.credential_remove_started first (so a call that happened is in the
// ledger whatever follows), the outcome is one transaction. A credential is
// "removed" only when the provider confirmed and a re-read no longer shows it;
// what no API can remove is manual, never done.
func (s *Service) RemoveCredential(ctx context.Context, db *store.DB, tenant tenancy.ID, appID, factID, by, reason string) (*CredentialReport, error) {
	var app *store.OAuthApp
	var fact *store.OAuthFact
	if err := db.ReadTenant(ctx, tenant, func(tx *store.TenantTx) error {
		var err error
		if app, err = tx.OAuthApp(appID); err != nil {
			return err
		}
		fact, err = tx.OAuthFact(factID)
		return err
	}); errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	if fact.AppID != app.ID || fact.Status != "active" || (fact.Kind != CredSecret && fact.Kind != CredCertificate) {
		return nil, ErrNoCredential
	}
	rep := &CredentialReport{AppID: app.ID, App: app.Name, FactID: fact.ID, Label: fact.Label, Kind: fact.Kind}
	started := s.now()
	if err := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		return tx.Audit(started, by, "oauthapps.credential_remove_started", ojson.Object{{Key: "app_id", Value: app.ID},
			{Key: "credential_id", Value: fact.ID}, {Key: "kind", Value: fact.Kind}, {Key: "reason", Value: reason}})
	}); err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, s.budget())
	defer cancel()
	rep.Outcome, rep.Detail = s.removeAtProvider(callCtx, db, tenant, app, fact)
	rep.OK = rep.Outcome == OutcomeRemoved
	now := s.now()
	err := db.InTenant(ctx, tenant, func(tx *store.TenantTx) error {
		if rep.OK {
			if err := tx.SetOAuthFactStatus(fact.ID, "removed"); err != nil {
				return err
			}
			if err := closeCredentialChanges(tx, app.ID, fact.ID, by, now); err != nil {
				return err
			}
		}
		return tx.Audit(now, by, "oauthapps.credential_removed", ojson.Object{{Key: "app_id", Value: app.ID},
			{Key: "credential_id", Value: fact.ID}, {Key: "kind", Value: fact.Kind}, {Key: "outcome", Value: rep.Outcome},
			{Key: "reason", Value: reason}})
	})
	if err != nil {
		return nil, err
	}
	return rep, nil
}

func (s *Service) removeAtProvider(ctx context.Context, db *store.DB, tenant tenancy.ID, app *store.OAuthApp, fact *store.OAuthFact) (outcome, detail string) {
	cred, why, err := s.credential(ctx, db, tenant, app.Provider)
	if err != nil {
		return OutcomeFailed, errText(err)
	}
	if cred == nil {
		return OutcomeManual, "no provider credential (" + why + "): remove it in the provider's console"
	}
	prov, err := s.provider(app.Provider, cred)
	if err != nil {
		return OutcomeFailed, errText(err)
	}
	rm, ok := prov.(CredentialRemover)
	if !ok {
		return OutcomeManual, "no API removes a credential of this provider: remove it in the provider's console"
	}
	c := Credential{Key: fact.Key, Ref: fact.ProviderRef, Kind: fact.Kind, Label: fact.Label}
	err = rm.RemoveCredential(ctx, c)
	var me *ManualError
	switch {
	case errors.As(err, &me):
		return OutcomeManual, me.Msg
	case err != nil:
		return OutcomeFailed, errText(err)
	}
	present, err := rm.CredentialPresent(ctx, c)
	switch {
	case err != nil:
		return OutcomeFailed, "the provider accepted the removal but the re-read failed: " + errText(err)
	case present:
		return OutcomeFailed, "the provider accepted the removal but a re-read still shows the credential"
	}
	return OutcomeRemoved, ""
}

// closeCredentialChanges closes the open credential changes that name the fact.
func closeCredentialChanges(tx *store.TenantTx, appID, factID, by string, now time.Time) error {
	cs, err := tx.OAuthChangesOf(appID)
	if err != nil {
		return err
	}
	for _, c := range cs {
		var d struct {
			FactID string `json:"fact_id"`
		}
		if c.Status == store.OAuthChangeOpen && c.Kind == store.OAuthChangeCredential && json.Unmarshal(c.Detail, &d) == nil && d.FactID == factID {
			if err := tx.ResolveOAuthChangeID(c.ID, "credential removed by "+by, now); err != nil {
				return err
			}
		}
	}
	return nil
}
