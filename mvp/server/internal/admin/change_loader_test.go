package admin_test

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// groups.loader.save (issue #53, GR-10): the creation or change of a loader
// that runs a SQL query is a two-person change; it is filed by a caller whose
// route has checked groups.loader.admin, step-up and the folder privilege, and
// approved by another admin.

func loaderFolder(h *harness) string {
	var id string
	h.tx(func(tx *store.TenantTx) error {
		root := &store.Folder{CreatedAt: h.clk.now()}
		if err := tx.InsertGrpFolder(root); err != nil {
			return err
		}
		id = string(root.ID)
		return nil
	})
	return id
}

func sqlSpec(folder, name string) string {
	return fmt.Sprintf(`{"name":%q,"type":"sql_group_list","target_folder":%q,"config":{"database":"hr.db",`+
		`"query":"SELECT department AS group_name, external_id AS subject_id FROM identities"}}`, name, folder)
}

func TestLoaderSave_NeedsASecondAdmin(t *testing.T) {
	h := newHarness(t)
	admins := h.admins("ada", "ben")
	pa := h.user("pat", "policy_admin")
	requester := h.as(pa)
	folder := loaderFolder(h)
	file := func(spec string) string { return `{"spec":` + spec + `}` }

	if !slices.Contains(admin.Types(), admin.TypeGroupLoaderSave) {
		t.Fatalf("the change types %v lack groups.loader.save", admin.Types())
	}
	// Submit is for admins; the loaders route files this one for a policy admin
	if _, err := h.submit(requester, admin.TypeGroupLoaderSave, file(sqlSpec(folder, "HR"))); err == nil {
		t.Error("a policy admin filed a change through the generic route")
	}
	if _, err := h.svc.SubmitChecked(h.ctx, requester, admin.SubmitInput{Type: admin.TypeRoleGrant, Payload: []byte(`{}`)}); err == nil {
		t.Error("SubmitChecked filed a type other than groups.loader.save")
	} else {
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	}
	if _, err := h.svc.SubmitChecked(h.ctx, &auth.Principal{Kind: auth.KindUser, TenantID: tenantID}, admin.SubmitInput{Type: admin.TypeGroupLoaderSave,
		Payload: []byte(file(sqlSpec(folder, "HR")))}); err == nil {
		t.Error("SubmitChecked filed a request for no one")
	}

	submit := func(payload string) (*store.AdminChange, error) {
		return h.svc.SubmitChecked(h.ctx, requester, admin.SubmitInput{Type: admin.TypeGroupLoaderSave, Payload: []byte(payload)})
	}
	// the plan refuses what cannot be saved, before anyone is asked
	for name, c := range map[string]struct {
		payload string
		status  int
		code    string
	}{
		"csv loader":     {file(fmt.Sprintf(`{"name":"C","type":"csv","target_folder":%q,"config":{"path":"a.csv","group":"g","subject_column":"id"}}`, folder)), 422, "invalid_payload"},
		"unknown folder": {file(sqlSpec("00000000-0000-4000-8000-00000000dead", "HR")), 422, "unknown_folder"},
		"query writes":   {file(fmt.Sprintf(`{"name":"W","type":"sql_simple","target_folder":%q,"config":{"database":"hr.db","group":"g","query":"DELETE FROM identities"}}`, folder)), 422, "invalid_config"},
		"unknown loader": {`{"loader_id":"00000000-0000-4000-8000-00000000dead","spec":` + sqlSpec(folder, "HR") + `}`, 404, "not_found"},
		"unknown field":  {`{"spec":` + sqlSpec(folder, "HR") + `,"extra":1}`, 422, "invalid_payload"},
		"no spec":        {`{}`, 422, "invalid_name"},
	} {
		if _, err := submit(c.payload); err == nil {
			t.Errorf("%s: filed", name)
		} else {
			var ae *admin.Error
			if !errors.As(err, &ae) || ae.Status != c.status || ae.Code != c.code {
				t.Errorf("%s: %v, want %d %s", name, err, c.status, c.code)
			}
		}
	}

	ch, err := submit(file(sqlSpec(folder, "HR")))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Status != store.ChangePendingApproval || !ch.TwoPerson || ch.CoolingOffSeconds != 0 || ch.RequestedBy != pa.ID {
		t.Fatalf("request = %+v", ch)
	}
	h.tx(func(tx *store.TenantTx) error {
		if ls, err := tx.GrpLoaders(); err != nil || len(ls) != 0 {
			t.Errorf("the loader exists before it is approved: %v, %v", ls, err)
		}
		return nil
	})
	// the requester cannot approve; another admin does, and the loader exists, made by the requester
	if _, err := h.svc.Approve(h.ctx, requester, ch.ID, ch.PayloadHash); err == nil {
		t.Error("the requester approved their own change")
	}
	done, err := h.svc.Approve(h.ctx, h.as(admins[0]), ch.ID, ch.PayloadHash)
	if err != nil || done.Status != store.ChangeApplied {
		t.Fatalf("approve = %+v, %v", done, err)
	}
	var l *store.GrpLoader
	h.tx(func(tx *store.TenantTx) error {
		var err error
		l, err = tx.GrpLoaderByName("hr")
		return err
	})
	if l == nil || l.Type != "sql_group_list" || l.CreatedBy == nil || *l.CreatedBy != pa.ID.String() || l.Version != 1 {
		t.Fatalf("loader = %+v", l)
	}
	acts := h.audited(tenantID)
	for _, want := range []string{"admin.change.submitted", "admin.change.approved", "admin.change.applied", "groups.loader.created"} {
		if !slices.Contains(acts, want) {
			t.Errorf("audit %v lacks %s", acts, want)
		}
	}

	// a change to it, filed against the version it saw; if the loader moves on first, the apply fails and changes nothing
	body := fmt.Sprintf(`{"loader_id":%q,"version":1,"spec":%s}`, l.ID, sqlSpec(folder, "HR renamed"))
	upd, err := submit(body)
	if err != nil {
		t.Fatal(err)
	}
	h.tx(func(tx *store.TenantTx) error { return tx.SetGrpLoaderStatus(l.ID, store.LoaderDisabled, h.clk.now()) })
	h.tx(func(tx *store.TenantTx) error {
		cur, err := tx.GrpLoader(l.ID)
		if err != nil {
			return err
		}
		cur.Schedule = "@hourly"
		return tx.UpdateGrpLoader(cur) // version 2
	})
	if _, err := h.svc.Approve(h.ctx, h.as(admins[1]), upd.ID, upd.PayloadHash); err == nil {
		t.Error("a request made against version 1 was approved for version 2")
	} else {
		wantErr(t, err, http.StatusConflict, "version_conflict")
	}
	// a name that is taken, a change nobody may make twice
	if _, err := submit(file(sqlSpec(folder, "hr"))); err == nil {
		t.Error("a second loader of the same name was filed")
	} else {
		wantErr(t, err, http.StatusConflict, "name_taken")
	}
}

// TestLoaderSave_BootstrapAdmins: with fewer than two active admins nobody can
// approve, so the request is refused up front like every two-person change.
func TestLoaderSave_BootstrapAdmins(t *testing.T) {
	h := newHarness(t)
	h.admins("ada")
	pa := h.user("pat", "policy_admin")
	folder := loaderFolder(h)
	_, err := h.svc.SubmitChecked(h.ctx, h.as(pa), admin.SubmitInput{Type: admin.TypeGroupLoaderSave,
		Payload: []byte(`{"spec":` + sqlSpec(folder, "HR") + `}`)})
	wantErr(t, err, http.StatusConflict, "bootstrap_restricted")
}
