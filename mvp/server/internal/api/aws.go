package api

import (
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/awsorg"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// AWS connector routes (issue #26, PR-7; design
// docs/design/aws-effective-permission-evaluator.md §11.1). The connector is
// read-only against AWS: it assumes a customer role with an external id and
// collects snapshots (internal/connectors/awsorg). These routes manage the
// connectors and list what they collected; the evaluator endpoints
// (/api/aws/can and the rest of §11.2) arrive with PR-11. They use the
// connections.* permissions. Credentials are sealed on write and never
// returned: a connector shows "credentials_set" only.
//
//	GET    /api/aws/connectors        the tenant's connectors, with their last run
//	POST   /api/aws/connectors        {name, config, credentials}; the response carries the external_id for the role's trust policy
//	DELETE /api/aws/connectors/{id}
//	GET    /api/aws/snapshots         newest first
//	GET    /api/aws/snapshots/{id}    one snapshot with its collection findings
//
// Running a collection is not a route yet: a run can outlast the request
// timeout, so it needs the background runner (awsorg.Service.Collect).
func (s *Server) registerAWSRoutes() {
	G, P, D := http.MethodGet, http.MethodPost, http.MethodDelete
	s.handle(G, "/api/aws/connectors", read, need(auth.PermConnectionsRead), s.rd(s.listAWSConnectors))
	s.handle(P, "/api/aws/connectors", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.createAWSConnector))
	s.handle(D, "/api/aws/connectors/{id}", write, needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy), s.rd(s.deleteAWSConnector))
	s.handle(G, "/api/aws/snapshots", read, need(auth.PermConnectionsRead), s.rd(s.listAWSSnapshots))
	s.handle(G, "/api/aws/snapshots/{id}", read, need(auth.PermConnectionsRead), s.rd(s.getAWSSnapshot))
}

func (s *Server) awsService() *awsorg.Service {
	return &awsorg.Service{Sealer: s.cfg.Sealer, Clock: s.clock}
}

var awsSnapshotIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// awsErr maps the service's refusals to API errors.
func awsErr(err error) error {
	var ie *awsorg.InputError
	if errors.As(err, &ie) {
		status := map[string]int{"invalid": http.StatusUnprocessableEntity, "conflict": http.StatusConflict, "not_found": http.StatusNotFound}[ie.Kind]
		return &readiness.Error{Status: status, Code: ie.Code, Msg: ie.Msg}
	}
	return err
}

type awsConnectorView struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Config         awsorg.Config `json:"config"`
	ExternalID     string        `json:"external_id"`
	CredentialsSet bool          `json:"credentials_set"`
	Status         string        `json:"status"`
	LastSnapshotID string        `json:"last_snapshot_id"`
	LastRunAt      *string       `json:"last_run_at"`
	LastError      string        `json:"last_error"`
	CreatedBy      string        `json:"created_by"`
	CreatedAt      string        `json:"created_at"`
}

func awsConnectorViewOf(k *store.AWSConnector) (awsConnectorView, error) {
	cfg, err := awsorg.ParseConfig(k.Config)
	if err != nil {
		return awsConnectorView{}, err
	}
	return awsConnectorView{ID: k.ID, Name: k.Name, Config: *cfg, ExternalID: k.ExternalID, CredentialsSet: len(k.CredentialsEnc) > 0,
		Status: k.Status, LastSnapshotID: k.LastSnapshotID, LastRunAt: awsRT(k.LastRunAt), LastError: k.LastError, CreatedBy: k.CreatedBy,
		CreatedAt: store.RT(k.CreatedAt)}, nil
}

func awsRT(t *time.Time) *string {
	if t == nil {
		return nil
	}
	v := store.RT(*t)
	return &v
}

func (s *Server) listAWSConnectors(r *http.Request, _ *params) (int, any, error) {
	all, err := store.TxFrom(r.Context()).AWSConnectors()
	if err != nil {
		return 0, nil, err
	}
	items := make([]awsConnectorView, 0, len(all))
	for _, k := range all {
		v, err := awsConnectorViewOf(k)
		if err != nil {
			return 0, nil, err
		}
		items = append(items, v)
	}
	return http.StatusOK, map[string]any{"items": items, "reader_actions": awsorg.ReaderActions,
		"max_regions": awsorg.MaxRegions, "max_accounts": awsorg.MaxAccounts}, nil
}

func (s *Server) createAWSConnector(r *http.Request, _ *params) (int, any, error) {
	var in struct {
		Name        string             `json:"name"`
		Config      awsorg.Config      `json:"config"`
		Credentials awsorg.Credentials `json:"credentials"`
	}
	if err := decodeBody(r, &in, false); err != nil {
		return 0, nil, err
	}
	var out awsConnectorView
	err := s.write(r, func(c *store.TenantTx, now time.Time) error {
		k, err := s.awsService().CreateConnector(c, awsorg.CreateInput{Name: in.Name, Config: in.Config, Credentials: in.Credentials}, actor(r), now)
		if err != nil {
			return err
		}
		out, err = awsConnectorViewOf(k)
		return err
	})
	if err != nil {
		return 0, nil, awsErr(err)
	}
	return http.StatusCreated, out, nil
}

func (s *Server) deleteAWSConnector(r *http.Request, p *params) (int, any, error) {
	id, err := connID(p)
	if err != nil {
		return 0, nil, err
	}
	err = s.write(r, func(c *store.TenantTx, now time.Time) error {
		return s.awsService().DeleteConnector(c, id, actor(r), now)
	})
	if err != nil {
		return 0, nil, awsErr(err)
	}
	return http.StatusOK, map[string]any{"id": id, "deleted": true}, nil
}

type awsSnapshotView struct {
	ID             string   `json:"id"`
	TakenAt        string   `json:"taken_at"`
	OrgID          string   `json:"org_id"`
	AccountIDs     []string `json:"account_ids"`
	CatalogVersion string   `json:"catalog_version"`
	Source         string   `json:"source"`
	ConnectorID    string   `json:"connector_id"`
}

func awsSnapshotViewOf(x *store.AWSSnapshot) awsSnapshotView {
	ids := x.AccountIDs
	if ids == nil {
		ids = []string{}
	}
	return awsSnapshotView{ID: x.ID, TakenAt: store.RT(x.TakenAt), OrgID: x.OrgID, AccountIDs: ids, CatalogVersion: x.CatalogVersion,
		Source: x.Source, ConnectorID: x.ConnectorID}
}

func (s *Server) listAWSSnapshots(r *http.Request, _ *params) (int, any, error) {
	all, err := store.TxFrom(r.Context()).AWSSnapshots(100)
	if err != nil {
		return 0, nil, err
	}
	items := make([]awsSnapshotView, 0, len(all))
	for _, x := range all {
		items = append(items, awsSnapshotViewOf(x))
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

func (s *Server) getAWSSnapshot(r *http.Request, p *params) (int, any, error) {
	id := p.path["id"]
	notFound := &readiness.Error{Status: http.StatusNotFound, Code: "not_found", Msg: "no such snapshot"}
	if !awsSnapshotIDRE.MatchString(id) {
		return 0, nil, notFound
	}
	tx := store.TxFrom(r.Context())
	x, err := tx.AWSSnapshot(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil, notFound
		}
		return 0, nil, err
	}
	fs, err := tx.AWSFindings(id)
	if err != nil {
		return 0, nil, err
	}
	type findingView struct {
		Kind       string `json:"kind"`
		SourceARN  string `json:"source_arn"`
		PolicyKind string `json:"policy_kind"`
		Code       string `json:"code"`
		Detail     string `json:"detail"`
	}
	findings := make([]findingView, 0, len(fs))
	for _, f := range fs {
		findings = append(findings, findingView{f.Kind, f.SourceARN, f.PolicyKind, f.Code, f.Detail})
	}
	return http.StatusOK, map[string]any{"snapshot": awsSnapshotViewOf(x), "findings": findings}, nil
}
