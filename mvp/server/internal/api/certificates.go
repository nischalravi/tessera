package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/certs"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Certificates (Admin > Certificates):
//
//	GET  /api/admin/certificates                      every certificate and key Tessera holds, with where it is used
//	POST /api/admin/certificates                      upload a PEM certificate with its private key (sealed; never returned)
//	POST /api/admin/certificates/generate             {connection_id}: a new SAML SP key pair, published beside the active one
//	POST /api/admin/certificates/{certificate_id}/promote   make a waiting SAML SP certificate the signing one; retires the old
//	POST /api/admin/certificates/{certificate_id}/retire    retire a certificate (or discard a waiting one) and destroy its key
//
// Changes need a fresh sign-in (step-up) and write their audit event in the same transaction. Listing needs
// connections.read; changing needs connections.manage. Expiry alerts come from the daily queue job
// (jobs.CertificateExpiry), not from these routes.

func (s *Server) registerCertificateRoutes() {
	manage := needStepUp(auth.PermConnectionsManage, auth.StepUpPolicy)
	s.handle(http.MethodGet, "/api/admin/certificates", read, need(auth.PermConnectionsRead), s.listCertificates)
	s.handle(http.MethodPost, "/api/admin/certificates", write, manage, s.uploadCertificate)
	s.handle(http.MethodPost, "/api/admin/certificates/generate", write, manage, s.generateCertificate)
	s.handle(http.MethodPost, "/api/admin/certificates/{certificate_id}/promote", write, manage, s.promoteCertificate)
	s.handle(http.MethodPost, "/api/admin/certificates/{certificate_id}/retire", write, manage, s.retireCertificate)
}

func certErr(err error) error {
	var ce *certs.Error
	if errors.As(err, &ce) {
		return &readiness.Error{Status: ce.Status, Code: ce.Code, Msg: ce.Msg}
	}
	return err
}

func certActor(r *http.Request) (string, error) {
	pr := principal(r)
	if pr.UserID == nil {
		return "", &readiness.Error{Status: http.StatusForbidden, Code: "user_required", Msg: "only a signed-in user can do this"}
	}
	return pr.Display, nil
}

type certView struct {
	ID            string     `json:"id"`
	Source        string     `json:"source"`
	Purpose       string     `json:"purpose"`
	Label         string     `json:"label"`
	Status        string     `json:"status"`
	UsedBy        string     `json:"used_by"`
	Subject       string     `json:"subject"`
	Issuer        string     `json:"issuer"`
	SANs          []string   `json:"sans"`
	NotBefore     *time.Time `json:"not_before"`
	NotAfter      *time.Time `json:"not_after"`
	DaysLeft      *int       `json:"days_left"`
	ExpiryWarning int        `json:"expiry_warning"` // 0, 30 or 7: the warning bucket it is in
	Fingerprint   string     `json:"fingerprint_sha256"`
	KeyAlgorithm  string     `json:"key_algorithm"`
	SigAlgorithm  string     `json:"signature_algorithm"`
	ConnectionID  *string    `json:"connection_id"`
	CanPromote    bool       `json:"can_promote"`
	CanRetire     bool       `json:"can_retire"`
}

func viewCert(e certs.Entry, now time.Time) certView {
	v := certView{ID: e.ID, Source: e.Source, Purpose: e.Purpose, Label: e.Label, Status: e.Status, UsedBy: e.UsedBy, Subject: e.Subject,
		Issuer: e.Issuer, SANs: append([]string{}, e.SANs...), NotBefore: e.NotBefore, NotAfter: e.NotAfter, Fingerprint: e.Fingerprint,
		KeyAlgorithm: e.KeyAlgorithm, SigAlgorithm: e.SigAlgorithm, ConnectionID: e.IdPConnID}
	if e.NotAfter != nil {
		d := certs.DaysLeft(now, *e.NotAfter)
		v.DaysLeft = &d
		if e.Status != store.CertRetired {
			v.ExpiryWarning = certs.Bucket(now, *e.NotAfter)
		}
	}
	v.CanPromote = e.Manageable && e.Purpose == store.CertSAMLSP && e.Status == store.CertNext
	v.CanRetire = e.Manageable && e.Status != store.CertRetired && !(e.Purpose == store.CertSAMLSP && e.Status == store.CertActive)
	return v
}

func (s *Server) certView(tx *store.TenantTx, id string, now time.Time) (certView, error) {
	all, err := certs.Inventory(tx, now)
	if err != nil {
		return certView{}, err
	}
	for _, e := range all {
		if e.ID == "cert:"+id {
			return viewCert(e, now), nil
		}
	}
	// a promoted SAML SP certificate is listed once, as the connection's own
	row, err := tx.Certificate(id)
	if err != nil {
		return certView{}, err
	}
	for _, e := range all {
		if e.Fingerprint == row.Fingerprint && e.Purpose == row.Purpose {
			return viewCert(e, now), nil
		}
	}
	return certView{}, errStatus(http.StatusNotFound, "Not Found")
}

func (s *Server) listCertificates(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	all, err := certs.Inventory(tx, now)
	if err != nil {
		return nil, err
	}
	out := make([]certView, 0, len(all))
	for _, e := range all {
		out = append(out, viewCert(e, now))
	}
	return out, nil
}

type uploadCertBody struct {
	Purpose      string  `json:"purpose"`
	Label        string  `json:"label"`
	Certificate  string  `json:"certificate_pem"`
	PrivateKey   string  `json:"private_key_pem"`
	ConnectionID *string `json:"connection_id"` // saml_sp: the SAML connection; mtls_client: the connector (optional)
}

func (s *Server) uploadCertificate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := certActor(r)
	if err != nil {
		return nil, err
	}
	var b uploadCertBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	u := certs.Upload{Purpose: b.Purpose, Label: b.Label, CertPEM: b.Certificate, KeyPEM: b.PrivateKey}
	if b.ConnectionID != nil {
		switch b.Purpose {
		case store.CertSAMLSP:
			id, err := uuid.Parse(*b.ConnectionID)
			if err != nil {
				return nil, badRequest("invalid_connection", "connection_id is not a connection id")
			}
			u.IdPConnectionID = &id
		default:
			u.ConnectionID = b.ConnectionID
		}
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	c, err := certs.UploadCertificate(tx, s.cfg.Sealer, u, by, now)
	if err != nil {
		return nil, certErr(err)
	}
	v, err := s.certView(tx, c.ID, now)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

type generateCertBody struct {
	ConnectionID string `json:"connection_id"`
}

func (s *Server) generateCertificate(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	by, err := certActor(r)
	if err != nil {
		return nil, err
	}
	var b generateCertBody
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(b.ConnectionID)
	if err != nil {
		return nil, badRequest("invalid_connection", "connection_id is not a connection id")
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	c, err := certs.GenerateSAML(tx, s.cfg.Sealer, id, by, now)
	if err != nil {
		return nil, certErr(err)
	}
	v, err := s.certView(tx, c.ID, now)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, v}, nil
}

func (s *Server) promoteCertificate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := certActor(r)
	if err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	c, err := certs.Promote(tx, s.cfg.Sealer, p.path["certificate_id"], by, now)
	if err != nil {
		return nil, certErr(err)
	}
	return s.certView(tx, c.ID, now)
}

func (s *Server) retireCertificate(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	by, err := certActor(r)
	if err != nil {
		return nil, err
	}
	tx, now := store.TxFrom(r.Context()), s.clock().UTC()
	c, err := certs.Retire(tx, p.path["certificate_id"], by, now)
	if err != nil {
		return nil, certErr(err)
	}
	return s.certView(tx, c.ID, now)
}
