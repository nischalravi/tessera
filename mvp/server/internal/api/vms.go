package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	feed "github.com/nischalravi/tessera/mvp/server/internal/connectors/vms"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/queue"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/vms"
)

// Contractor (VMS) feeds (issue #304; internal/vms, internal/intake/vms.go):
//
//	GET    /api/vms/sources                       the tenant's feeds with their last sync
//	POST   /api/vms/sources                       {vendor, name, base_url?, settings?, credential?, status?}
//	PUT    /api/vms/sources/{source_id}           {name, base_url?, settings?, credential?, status?}
//	DELETE /api/vms/sources/{source_id}           removes the feed (the contractors it brought stay)
//	POST   /api/vms/sync                          {source_id?}: read the feeds now
//	POST   /api/vms/sources/{source_id}/import    the CSV as the body (a CSV source)
//	GET    /api/vms/records?limit=                the newest contractor records and what became of each
//
// vendor is fieldglass, beeline or csv. The credential is write-only: sealed
// under the KEK, bound to the source, never returned. An edit that moves the
// base URL needs a new one. A record becomes an intake event of channel vms;
// every contractor needs a sponsor (a record without one is held in review and
// creates nobody) and its end date drives the leaver plan (the lifecycle
// sweep). Reading needs connections.read, changing a feed connections.manage,
// reading one now or importing a file lifecycle.manage (it creates and ends people).

const (
	maxVmsCredential = 4096
	vmsSyncTimeout   = 2 * time.Minute
	// vmsSyncEvery is how often each tenant's contractor feeds are read; a source
	// that is paused, or an upload-only file, is skipped.
	vmsSyncEvery       = time.Hour
	maxVmsSyncAttempts = 2
	vmsSyncActor       = "vms.sync"
)

// queueVmsSync is the queue handler of the feed read. A tenant with no feed to
// read leaves no job run; a feed that failed makes the run fail, so the run
// history shows it.
func (s *Server) queueVmsSync(ctx context.Context, j queue.Job) (any, error) {
	reps, err := s.vms.Sync(audit.WithSystemActor(ctx, vmsSyncActor), j.Tenant)
	if err != nil {
		return nil, err
	}
	var failed []string
	read := false
	for _, r := range reps {
		read = read || r.Status != vms.StatusSkipped
		if r.Status == vms.StatusFailed {
			failed = append(failed, r.Name)
		}
	}
	if !read {
		return nil, nil
	}
	if len(failed) > 0 {
		return reps, fmt.Errorf("vms sync failed for %s", strings.Join(failed, ", "))
	}
	return reps, nil
}

var vmsNameRE = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._()-]{0,99}$`)

func (s *Server) registerVmsRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/vms/sources", read, need(auth.PermConnectionsRead), s.listVmsSources)
	s.handle(P, "/api/vms/sources", write, need(auth.PermConnectionsManage), s.createVmsSource)
	s.handle(http.MethodPut, "/api/vms/sources/{source_id}", write, need(auth.PermConnectionsManage), s.updateVmsSource)
	s.handle(http.MethodDelete, "/api/vms/sources/{source_id}", write, need(auth.PermConnectionsManage), s.deleteVmsSource)
	s.handle(P, "/api/vms/sync", phased, need(auth.PermLifecycleManage), s.syncVms)
	s.handle(P, "/api/vms/sources/{source_id}/import", phased, Route{Perm: auth.PermLifecycleManage, BodyType: "text/csv"}, s.importVms)
	s.handle(G, "/api/vms/records", read, need(auth.PermConnectionsRead), s.listVmsRecords)
}

type vmsSourceView struct {
	ID            string         `json:"id"`
	Vendor        string         `json:"vendor"`
	Name          string         `json:"name"`
	BaseURL       string         `json:"base_url"`
	Settings      feed.Settings  `json:"settings"`
	HasCredential bool           `json:"has_credential"`
	Status        string         `json:"status"`
	LastSyncAt    *string        `json:"last_sync_at"`
	LastResult    *string        `json:"last_result"`
	LastError     *string        `json:"last_error"`
	LastCounts    map[string]int `json:"last_counts"`
	Cursor        *string        `json:"cursor"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
}

func viewVmsSource(v *store.VmsSource) vmsSourceView {
	out := vmsSourceView{ID: v.ID, Vendor: v.Vendor, Name: v.Name, BaseURL: v.BaseURL, HasCredential: len(v.CredentialEnc) > 0,
		Status: v.Status, LastSyncAt: isoPtr(v.LastSyncAt), LastResult: v.LastResult, LastError: v.LastError,
		Cursor: isoPtr(v.Cursor), CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: v.UpdatedAt.UTC().Format(time.RFC3339), LastCounts: map[string]int{}}
	_ = json.Unmarshal([]byte(v.Settings), &out.Settings)
	_ = json.Unmarshal([]byte(v.LastCounts), &out.LastCounts)
	return out
}

func (s *Server) listVmsSources(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	all, err := store.TxFrom(r.Context()).VmsSources()
	if err != nil {
		return nil, err
	}
	out := make([]vmsSourceView, 0, len(all))
	for _, v := range all {
		out = append(out, viewVmsSource(v))
	}
	return map[string]any{"sources": out}, nil
}

type vmsSourceInput struct {
	Vendor     string        `json:"vendor"`
	Name       string        `json:"name"`
	BaseURL    string        `json:"base_url"`
	Settings   feed.Settings `json:"settings"`
	Credential string        `json:"credential"`
	Status     string        `json:"status"`
}

func vmsID(p *params) (string, error) {
	id := p.path["source_id"]
	if !idRE.MatchString(id) {
		return "", notFoundErr("source")
	}
	return id, nil
}

// validateVmsSource checks the input of a create or an edit.
func (s *Server) validateVmsSource(in *vmsSourceInput, vendor string) error {
	in.Name = strings.TrimSpace(in.Name)
	in.BaseURL = strings.TrimSpace(in.BaseURL)
	switch {
	case !vmsNameRE.MatchString(in.Name):
		return badRequest("invalid_name", "name is 1 to 100 letters, digits, spaces or . _ ( ) -")
	case in.Status != "" && in.Status != store.VmsActive && in.Status != store.VmsPaused:
		return badRequest("invalid_status", "status is active or paused")
	case len(in.Credential) > maxVmsCredential:
		return badRequest("invalid_credential", "the credential is longer than 4 KiB")
	case vendor != store.VmsCSV && in.BaseURL == "":
		return badRequest("invalid_base_url", "base_url is required for "+vendor)
	}
	if err := s.vms.ValidBaseURL(in.BaseURL); err != nil {
		return badRequest("invalid_base_url", err.Error())
	}
	if err := in.Settings.Validate(vendor); err != nil {
		return badRequest("invalid_settings", err.Error())
	}
	if vendor == store.VmsCSV && (in.BaseURL == "") != (in.Settings.CSVPath == "") {
		return badRequest("invalid_settings", "base_url and csv_path go together: set both to fetch a file, neither to upload it")
	}
	if in.Credential != "" && vendor != store.VmsCSV {
		if _, _, err := feed.ParseCredential(in.Credential); err != nil {
			return badRequest("invalid_credential", err.Error())
		}
	}
	return nil
}

func (s *Server) vmsErr(err error) error {
	if errors.Is(err, store.ErrVmsNameTaken) {
		return &readiness.Error{Status: http.StatusConflict, Code: "name_taken", Msg: "a feed with this name exists"}
	}
	return err
}

func settingsJSON(set feed.Settings) (string, error) {
	b, err := json.Marshal(set)
	return string(b), err
}

func (s *Server) createVmsSource(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var in vmsSourceInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	switch in.Vendor {
	case store.VmsFieldglass, store.VmsBeeline, store.VmsCSV:
	default:
		return nil, badRequest("invalid_vendor", "vendor is fieldglass, beeline or csv")
	}
	if err := s.validateVmsSource(&in, in.Vendor); err != nil {
		return nil, err
	}
	if in.Vendor != store.VmsCSV && in.Credential == "" {
		return nil, badRequest("credential_required", "a Fieldglass or Beeline feed needs its client id and secret (client_id:client_secret)")
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	settings, err := settingsJSON(in.Settings)
	if err != nil {
		return nil, err
	}
	v := &store.VmsSource{ID: store.NewID(), Vendor: in.Vendor, Name: in.Name, BaseURL: in.BaseURL, Settings: settings,
		Status: store.VmsActive, CreatedBy: actor(r)}
	if in.Status != "" {
		v.Status = in.Status
	}
	if in.Credential != "" {
		if v.CredentialEnc, err = vms.SealCredential(s.provSeal, c.Tenant(), v.ID, in.Credential); err != nil {
			return nil, err
		}
		ver := store.NewID()
		v.CredentialVer = &ver
	}
	if err := c.InsertVmsSource(v, now); err != nil {
		return nil, s.vmsErr(err)
	}
	if err := c.Audit(now, actor(r), "vms.source_created", ojson.Object{{Key: "source_id", Value: v.ID},
		{Key: "vendor", Value: v.Vendor}, {Key: "origin", Value: targetOrigin(v.BaseURL)}, {Key: "credential", Value: credentialState(v)}}); err != nil {
		return nil, err
	}
	saved, err := c.VmsSource(v.ID)
	if err != nil {
		return nil, err
	}
	return statusBody{http.StatusCreated, viewVmsSource(saved)}, nil
}

func credentialState(v *store.VmsSource) string {
	if len(v.CredentialEnc) > 0 {
		return "set"
	}
	return "none"
}

func (s *Server) updateVmsSource(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := vmsID(p)
	if err != nil {
		return nil, err
	}
	var in vmsSourceInput
	if err := decodeBody(r, &in, false); err != nil {
		return nil, err
	}
	c, now := store.TxFrom(r.Context()), s.clock()
	old, err := c.VmsSource(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFoundErr("source")
	} else if err != nil {
		return nil, err
	}
	if in.Vendor != "" && in.Vendor != old.Vendor {
		return nil, badRequest("vendor_fixed", "the vendor of a feed cannot change: add a new feed")
	}
	if err := s.validateVmsSource(&in, old.Vendor); err != nil {
		return nil, err
	}
	settings, err := settingsJSON(in.Settings)
	if err != nil {
		return nil, err
	}
	v := *old
	v.Name, v.BaseURL, v.Settings = in.Name, in.BaseURL, settings
	if in.Status != "" {
		v.Status = in.Status
	}
	// The sealed credential is bound to the row, not to the destination, so a
	// stored one must never follow the feed to another origin (as for targets, #315).
	moved := targetOrigin(old.BaseURL) != targetOrigin(in.BaseURL)
	credential := credentialState(old)
	switch {
	case in.Credential != "":
		if v.CredentialEnc, err = vms.SealCredential(s.provSeal, c.Tenant(), v.ID, in.Credential); err != nil {
			return nil, err
		}
		ver := store.NewID()
		v.CredentialVer = &ver
		credential = "set"
		if len(old.CredentialEnc) > 0 {
			credential = "rotated"
		}
	case moved && len(old.CredentialEnc) > 0:
		return nil, &readiness.Error{Status: http.StatusUnprocessableEntity, Code: "credential_required",
			Msg: "changing the base URL needs a new credential; the stored one does not move with it"}
	case old.Vendor != store.VmsCSV && len(old.CredentialEnc) == 0:
		return nil, badRequest("credential_required", "a Fieldglass or Beeline feed needs its client id and secret")
	}
	if err := c.UpdateVmsSource(&v, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFoundErr("source")
		}
		return nil, s.vmsErr(err)
	}
	if err := c.Audit(now, actor(r), "vms.source_updated", ojson.Object{{Key: "source_id", Value: id},
		{Key: "vendor", Value: v.Vendor}, {Key: "origin", Value: targetOrigin(v.BaseURL)}, {Key: "status", Value: v.Status},
		{Key: "credential", Value: credential}}); err != nil {
		return nil, err
	}
	saved, err := c.VmsSource(id)
	if err != nil {
		return nil, err
	}
	return viewVmsSource(saved), nil
}

func (s *Server) deleteVmsSource(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := vmsID(p)
	if err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	if err := c.DeleteVmsSource(id); errors.Is(err, store.ErrNotFound) {
		return nil, notFoundErr("source")
	} else if err != nil {
		return nil, err
	}
	if err := c.Audit(s.clock(), actor(r), "vms.source_removed", ojson.Object{{Key: "source_id", Value: id}}); err != nil {
		return nil, err
	}
	return map[string]any{"removed": id}, nil
}

func (s *Server) syncVms(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var in struct {
		SourceID string `json:"source_id"`
	}
	if err := decodeBody(r, &in, true); err != nil {
		return nil, err
	}
	var only []string
	if in.SourceID != "" {
		if !idRE.MatchString(in.SourceID) {
			return nil, notFoundErr("source")
		}
		only = []string{in.SourceID}
	}
	ctx, cancel := context.WithTimeout(r.Context(), vmsSyncTimeout)
	defer cancel()
	reps, err := s.vms.Sync(ctx, principal(r).TenantID, only...)
	if err != nil {
		return nil, err
	}
	if len(only) == 1 && len(reps) == 0 {
		return nil, notFoundErr("source")
	}
	return map[string]any{"reports": reps}, nil
}

func (s *Server) importVms(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := vmsID(p)
	if err != nil {
		return nil, err
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "text/csv" {
			return nil, errStatus(http.StatusUnsupportedMediaType, "send the file as text/csv")
		}
	}
	rep, err := s.vms.Import(r.Context(), principal(r).TenantID, id, r.Body)
	var mbe *http.MaxBytesError
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, notFoundErr("source")
	case errors.As(err, &mbe):
		return nil, errBodyTooLarge
	case errors.Is(err, feed.ErrCSV):
		return nil, badRequest("invalid_file", strings.TrimPrefix(err.Error(), feed.ErrCSV.Error()+": "))
	case err != nil:
		return nil, badRequest("invalid_import", err.Error())
	}
	return rep, nil
}

type vmsRecordView struct {
	ID          string  `json:"id"`
	Source      string  `json:"source"` // the feed kind
	Status      string  `json:"status"` // received | review | resolved | rejected
	RecordState string  `json:"record_state"`
	Outcome     string  `json:"outcome"`
	Reason      string  `json:"reason,omitempty"`
	IdentityID  *int64  `json:"identity_id"`
	Person      *string `json:"person"`
	EffectiveAt *string `json:"effective_at"`
	CreatedAt   string  `json:"created_at"`
}

func (s *Server) listVmsRecords(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	one := int64(1)
	max := int64(500)
	limit := p.queryInt("limit", 100, &one, &max)
	if err := validated(p, nil); err != nil {
		return nil, err
	}
	c := store.TxFrom(r.Context())
	evs, err := c.IntakeEventsByChannel(store.ChannelVMS, int(limit))
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	out := make([]vmsRecordView, 0, len(evs))
	for _, e := range evs {
		v := vmsRecordView{ID: e.ID, Status: e.Status, RecordState: e.EventType, IdentityID: e.IdentityID,
			EffectiveAt: isoPtr(e.EffectiveAt), CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339)}
		if parts := strings.SplitN(e.EventKey, ":", 3); len(parts) == 3 {
			v.Source = parts[1]
		}
		var d struct {
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
		}
		_ = json.Unmarshal([]byte(e.Detail), &d)
		v.Outcome, v.Reason = d.Outcome, d.Reason
		if e.IdentityID != nil {
			n, ok := names[*e.IdentityID]
			if !ok {
				if p, err := c.Identity(*e.IdentityID); err == nil {
					n = p.Name
				}
				names[*e.IdentityID] = n
			}
			if n != "" {
				v.Person = &n
			}
		}
		out = append(out, v)
	}
	return map[string]any{"records": out}, nil
}
