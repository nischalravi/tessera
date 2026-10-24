package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/datasets"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Datasets (issue #588): named lookup tables that rules and request forms read by name.
//
//	GET    /api/datasets                       every dataset with its value count (graph.read)
//	POST   /api/datasets                       {name, description, values}: creates one
//	GET    /api/datasets/{id}?limit=&offset=   one, with a page of its values
//	PUT    /api/datasets/{id}                  {version, name, description}: renames or describes it
//	DELETE /api/datasets/{id}                  removes it and its values
//	POST   /api/datasets/{id}/values           {add: [...], remove: [...]}: adds and removes values
//	POST   /api/datasets/{id}/upload           a CSV body (text/csv), first column; ?header=true skips the
//	                                           first row, ?mode=replace makes the file the whole content
//	GET    /api/datasets/{id}/contains?value=  {contains}: membership of one value
//
// Writing needs catalog.manage (the dataset feeds request forms and rules) and is audited in the same
// transaction.
func (s *Server) registerDatasetRoutes() {
	const G, P, PU, D = http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete
	manage := need(auth.PermCatalogManage)
	s.handle(G, "/api/datasets", read, need(auth.PermGraphRead), s.listDatasets)
	s.handle(P, "/api/datasets", write, manage, s.createDataset)
	s.handle(G, "/api/datasets/{id}", read, need(auth.PermGraphRead), s.getDataset)
	s.handle(PU, "/api/datasets/{id}", write, manage, s.updateDataset)
	s.handle(D, "/api/datasets/{id}", write, manage, s.deleteDataset)
	s.handle(P, "/api/datasets/{id}/values", write, manage, s.editDatasetValues)
	s.handle(P, "/api/datasets/{id}/upload", write, Route{Perm: auth.PermCatalogManage, BodyType: "text/csv"}, s.uploadDataset)
	s.handle(G, "/api/datasets/{id}/contains", read, need(auth.PermGraphRead), s.datasetContains)
}

type datasetView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     int    `json:"version"`
	Count       int    `json:"count"`
	UpdatedBy   string `json:"updated_by"`
	UpdatedAt   string `json:"updated_at"`
}

func viewOf(d *store.Dataset) datasetView {
	return datasetView{d.ID, d.Name, d.Description, d.Version, d.Count, d.UpdatedBy, d.UpdatedAt.UTC().Format(time.RFC3339)}
}

func datasetID(p *params) (string, error) {
	id := strings.TrimSpace(p.path["id"])
	if !idRE.MatchString(id) {
		return "", &readiness.Error{Status: http.StatusNotFound, Code: "dataset_not_found", Msg: "dataset not found"}
	}
	return id, nil
}

func (s *Server) listDatasets(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	ds, err := store.TxFrom(r.Context()).Datasets()
	if err != nil {
		return nil, err
	}
	out := make([]datasetView, 0, len(ds))
	for _, d := range ds {
		out = append(out, viewOf(d))
	}
	return map[string]any{"datasets": out, "can_manage": s.can(r, auth.PermCatalogManage),
		"limits": map[string]int{"datasets": datasets.MaxDatasets, "values": datasets.MaxValues, "value_length": datasets.MaxValueLen,
			"csv_bytes": datasets.MaxCSVBytes}}, nil
}

func (s *Server) createDataset(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	var b struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Values      []string `json:"values"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := datasets.Create(store.TxFrom(r.Context()), datasets.Spec{Name: b.Name, Description: b.Description, Values: b.Values},
		actor(r), s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return statusBody{http.StatusCreated, viewOf(d)}, nil
}

func intQuery(r *http.Request, key string) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil {
		return 0
	}
	return n
}

func (s *Server) getDataset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	d, err := datasets.Get(tx, id)
	if err != nil {
		return nil, cfgErr(err)
	}
	limit, offset := intQuery(r, "limit"), intQuery(r, "offset")
	vals, err := datasets.Page(tx, id, limit, offset)
	if err != nil {
		return nil, cfgErr(err)
	}
	return struct {
		datasetView
		Values []string `json:"values"`
	}{viewOf(d), vals}, nil
}

func (s *Server) updateDataset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	var b struct {
		Version     int    `json:"version"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	d, err := datasets.Update(store.TxFrom(r.Context()), id, b.Version, b.Name, b.Description, actor(r), s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return viewOf(d), nil
}

func (s *Server) deleteDataset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	if err := datasets.Delete(store.TxFrom(r.Context()), id, actor(r), s.clock().UTC()); err != nil {
		return nil, cfgErr(err)
	}
	return map[string]any{"deleted": true}, nil
}

func changeBody(c *datasets.Change) any {
	return map[string]any{"dataset": viewOf(c.Dataset), "added": c.Added, "removed": c.Removed}
}

func (s *Server) editDatasetValues(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	var b struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := decodeBody(r, &b, false); err != nil {
		return nil, err
	}
	c, err := datasets.Edit(store.TxFrom(r.Context()), id, b.Add, b.Remove, actor(r), s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return changeBody(c), nil
}

func (s *Server) uploadDataset(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	mode := q.Get("mode")
	if mode != "" && mode != "append" && mode != "replace" {
		return nil, badRequest("invalid_mode", "mode is append or replace")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, datasets.MaxCSVBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, errBodyUnreadable
	}
	c, err := datasets.Upload(store.TxFrom(r.Context()), id, raw, q.Get("header") == "true", mode == "replace", actor(r), s.clock().UTC())
	if err != nil {
		return nil, cfgErr(err)
	}
	return changeBody(c), nil
}

func (s *Server) datasetContains(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	id, err := datasetID(p)
	if err != nil {
		return nil, err
	}
	tx := store.TxFrom(r.Context())
	if _, err := datasets.Get(tx, id); err != nil {
		return nil, cfgErr(err)
	}
	has, err := tx.DatasetHas(id, strings.TrimSpace(r.URL.Query().Get("value")))
	if err != nil {
		return nil, err
	}
	return map[string]any{"contains": has}, nil
}
