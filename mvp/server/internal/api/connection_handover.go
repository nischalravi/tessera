package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/vms"
)

// handover is the first sync of a governed connection whose records are read
// by a feature that keeps its own sources: the contractor feeds (Settings,
// Contractors) and the AWS connectors (AWS). Activation creates that feature's
// source from the connection, through the feature's own code (the same sealing,
// the same validation, the same audit event as creating it by hand), and the
// feature reads it from then on (the contractor sync job; the AWS collection).
// It is idempotent by name: an existing source of the same name is kept as it
// is, and the activation says so.
func (s *Server) handover(c *store.TenantTx, ac readiness.ActiveConnection, t governed.Type, now time.Time) error {
	p, err := s.readiness.GovernedParams(c, ac, now)
	if err != nil {
		return err
	}
	var feature, id string
	switch t.ID {
	case governed.AWSOrg:
		feature = "aws_connector"
		id, err = handoverAWS(c, s.cfg.Sealer, ac.Name(), p, now)
	default:
		feature = "vms_source"
		id, err = handoverVMS(c, s.provSeal, ac.Name(), ac.ConnectionID(), t, p, now)
	}
	if errors.Is(err, errHandoverExists) {
		return c.Audit(now, "system", "connection.handover_exists", ojson.Object{{Key: "connection_id", Value: ac.ConnectionID()},
			{Key: "feature", Value: feature}, {Key: "reason", Value: "a source with this name already exists and was kept"}})
	}
	if err != nil {
		return err
	}
	return c.Audit(now, "system", "connection.handover", ojson.Object{{Key: "connection_id", Value: ac.ConnectionID()},
		{Key: "revision_id", Value: ac.RevisionID()}, {Key: "feature", Value: feature}, {Key: "source_id", Value: id}})
}

var errHandoverExists = errors.New("source exists")

func handoverVMS(c *store.TenantTx, sealer *seal.Sealer, name, connectionID string, t governed.Type, p governed.Params, now time.Time) (string, error) {
	set := wire.VmsSettings(p)
	if err := set.Validate(t.Vendor); err != nil {
		return "", err
	}
	raw, err := json.Marshal(set)
	if err != nil {
		return "", err
	}
	v := &store.VmsSource{ID: store.NewID(), Vendor: t.Vendor, Name: name, BaseURL: p.BaseURL, Settings: string(raw),
		Status: store.VmsActive, CreatedBy: "connection:" + connectionID}
	if p.Secret != "" {
		if v.CredentialEnc, err = vms.SealCredential(sealer, c.Tenant(), v.ID, p.Secret); err != nil {
			return "", err
		}
		ver := store.NewID()
		v.CredentialVer = &ver
	}
	if err := c.InsertVmsSource(v, now); err != nil {
		if errors.Is(err, store.ErrVmsNameTaken) {
			return "", sameVMSSource(c, v)
		}
		return "", err
	}
	if err := c.Audit(now, "system", "vms.source_created", ojson.Object{{Key: "source_id", Value: v.ID},
		{Key: "vendor", Value: v.Vendor}, {Key: "origin", Value: targetOrigin(v.BaseURL)}, {Key: "credential", Value: credentialState(v)}}); err != nil {
		return "", err
	}
	return v.ID, nil
}

func handoverAWS(c *store.TenantTx, sealer *seal.Sealer, name string, p governed.Params, now time.Time) (string, error) {
	var creds awsorg.Credentials
	if err := awsorg.ParseCredentials(p.Secret, &creds); err != nil {
		return "", err
	}
	k, err := (&awsorg.Service{Sealer: sealer}).CreateConnector(c, awsorg.CreateInput{Name: name, Config: awsorg.ConfigOf(p), Credentials: creds,
		ExternalID: p.Settings["external_id"]}, "system", now)
	var ie *awsorg.InputError
	if errors.As(err, &ie) && ie.Code == "name_taken" {
		return "", sameAWSConnector(c, name, p)
	}
	if err != nil {
		return "", err
	}
	return k.ID, nil
}

// handoverConflict: a source of the same name exists but is not this connection's. Activation
// fails rather than reporting success while the other source is the one that is read.
func handoverConflict(what string) error {
	return &readiness.Error{Status: http.StatusConflict, Code: "handover_conflict",
		Msg: "a " + what + " with this name already exists with different settings; rename one of them or remove the existing one"}
}

// sameVMSSource is errHandoverExists when the existing feed of the name is this connection's
// (same vendor and URL), else a conflict.
func sameVMSSource(c *store.TenantTx, v *store.VmsSource) error {
	all, err := c.VmsSources()
	if err != nil {
		return err
	}
	for _, x := range all {
		if x.Name == v.Name {
			if x.Vendor == v.Vendor && x.BaseURL == v.BaseURL && x.Settings == v.Settings {
				return errHandoverExists
			}
			return handoverConflict("contractor feed")
		}
	}
	return handoverConflict("contractor feed")
}

// sameAWSConnector is errHandoverExists when the existing connector of the name has this
// connection's external id and configuration, else a conflict.
func sameAWSConnector(c *store.TenantTx, name string, p governed.Params) error {
	all, err := c.AWSConnectors()
	if err != nil {
		return err
	}
	want := awsorg.ConfigOf(p)
	if want.Validate() != nil {
		return handoverConflict("AWS connector")
	}
	for _, k := range all {
		if k.Name == name {
			have, err := awsorg.ParseConfig(k.Config)
			if err == nil && k.ExternalID == p.Settings["external_id"] && reflect.DeepEqual(*have, want) {
				return errHandoverExists
			}
			return handoverConflict("AWS connector")
		}
	}
	return handoverConflict("AWS connector")
}
