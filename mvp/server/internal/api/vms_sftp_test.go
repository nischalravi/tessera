package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// TestVmsSFTPAPI: an SFTP contractor feed needs a pinned host key, keeps its credential write-only
// and bound to the server, and is managed with the same permission as an HTTPS feed (issue #961).
func TestVmsSFTPAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	now := storetest.Now
	srv := newIsolationServerWith(f, func(c *Config) { c.Sealer = testSealer() })
	h := srv.Handler()
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	viewer := signIn(t, f.DB, f.B.ID, authtest.User{Email: "v@b.example", Roles: []auth.Role{auth.RoleViewer}}, authtest.Phr, now)
	const pw = "sftp-pw-do-not-echo"
	hostKey := "SHA256:" + strings.Repeat("B", 43)
	sftpSet := func(mod func(m map[string]any)) map[string]any {
		m := map[string]any{"host": "sftp.agency.example", "port": 22, "path": "/drop/contractors.csv", "username": "feeds",
			"host_key": hostKey, "auth": "password"}
		if mod != nil {
			mod(m)
		}
		return m
	}
	body := func(name, cred string, sf map[string]any) string {
		m := map[string]any{"vendor": "csv", "name": name, "settings": map[string]any{"sftp": sf}}
		if cred != "" {
			m["credential"] = cred
		}
		return jsonStr(m)
	}

	if rec := reqDo(h, viewer, "POST", "/api/vms/sources", body("SFTP", pw, sftpSet(nil))); rec.Code != 403 {
		t.Errorf("viewer POST: %d", rec.Code)
	}
	bad := map[string]string{
		"no host key":       body("S1", pw, sftpSet(func(m map[string]any) { delete(m, "host_key") })),
		"junk host key":     body("S2", pw, sftpSet(func(m map[string]any) { m["host_key"] = "trust me" })),
		"traversal":         body("S3", pw, sftpSet(func(m map[string]any) { m["path"] = "/drop/../etc/x.csv" })),
		"not csv":           body("S4", pw, sftpSet(func(m map[string]any) { m["path"] = "/drop/x.bin" })),
		"metadata host":     body("S5", pw, sftpSet(func(m map[string]any) { m["host"] = "169.254.169.254" })),
		"no credential":     body("S6", "", sftpSet(nil)),
		"key auth, a word":  body("S7", pw, sftpSet(func(m map[string]any) { m["auth"] = "key" })),
		"a base url too":    jsonStr(map[string]any{"vendor": "csv", "name": "S8", "base_url": "https://a.example.com", "credential": pw, "settings": map[string]any{"sftp": sftpSet(nil)}}),
		"sftp and csv path": jsonStr(map[string]any{"vendor": "csv", "name": "S9", "credential": pw, "settings": map[string]any{"csv_path": "/a.csv", "sftp": sftpSet(nil)}}),
		"on fieldglass":     jsonStr(map[string]any{"vendor": "fieldglass", "name": "S10", "base_url": "https://a.example.com", "credential": "a:b", "settings": map[string]any{"sftp": sftpSet(nil)}}),
	}
	for name, b := range bad {
		rec := reqDo(h, admin, "POST", "/api/vms/sources", b)
		if rec.Code != 422 {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), pw) {
			t.Errorf("%s: the credential is in the response", name)
		}
	}

	rec := reqDo(h, admin, "POST", "/api/vms/sources", body("Agency drop", pw, sftpSet(nil)))
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), pw) {
		t.Error("the credential is in the response")
	}
	var src vmsSourceView
	_ = json.Unmarshal(rec.Body.Bytes(), &src)
	if !src.HasCredential || src.Settings.SFTP == nil || src.Settings.SFTP.HostKey != hostKey || src.Settings.SFTP.Auth != "password" {
		t.Fatalf("source = %+v", src)
	}
	// the stored credential is sealed
	if err := f.DB.ReadTenant(t.Context(), f.B.ID, func(c *store.TenantTx) error {
		v, err := c.VmsSource(src.ID)
		if err != nil || len(v.CredentialEnc) == 0 || strings.Contains(string(v.CredentialEnc), pw) || strings.Contains(v.Settings, pw) {
			t.Errorf("stored source = %+v, %v", v, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rec := reqDo(h, admin, "GET", "/api/vms/sources", ""); strings.Contains(rec.Body.String(), pw) {
		t.Error("the credential is listed")
	}
	// another tenant sees and changes nothing of it
	if rec := reqDo(h, adminA, "PUT", "/api/vms/sources/"+src.ID, body("Agency drop", pw, sftpSet(nil))); rec.Code != 404 {
		t.Errorf("cross-tenant PUT: %d", rec.Code)
	}
	// a new server, login or host key needs a new credential; an unchanged one keeps the stored credential
	edit := func(sf map[string]any, cred string) int {
		return reqDo(h, admin, "PUT", "/api/vms/sources/"+src.ID, body("Agency drop", cred, sf)).Code
	}
	if c := edit(sftpSet(func(m map[string]any) { m["path"] = "/drop/other.csv" }), ""); c != 200 {
		t.Errorf("a new path keeps the credential: %d", c)
	}
	for name, sf := range map[string]map[string]any{
		"host":     sftpSet(func(m map[string]any) { m["host"] = "evil.example" }),
		"user":     sftpSet(func(m map[string]any) { m["username"] = "other" }),
		"host key": sftpSet(func(m map[string]any) { m["host_key"] = "SHA256:" + strings.Repeat("C", 43) }),
		"port":     sftpSet(func(m map[string]any) { m["port"] = 2222 }),
	} {
		if c := edit(sf, ""); c != 422 {
			t.Errorf("a new %s without a credential: %d", name, c)
		}
		if c := edit(sf, "another-password"); c != 200 {
			t.Errorf("a new %s with a credential: %d", name, c)
		}
	}
}
