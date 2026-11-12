package vms_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/vms"
)

const sftpPW = "pw-correct-horse-battery"

// startSFTP serves dir over SFTP (read only) on loopback to the login "feeds" with one password.
func startSFTP(t *testing.T) (dir string, port int, fingerprint string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if dir, err = filepath.EvalSymlinks(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conf := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "feeds" && string(pw) == sftpPW {
			return nil, nil
		}
		return nil, os.ErrPermission
	}}
	conf.AddHostKey(hk)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				sc, chans, reqs, err := ssh.NewServerConn(c, conf)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						defer ch.Close()
						for r := range creqs {
							ok := r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == "sftp"
							_ = r.Reply(ok, nil)
							if ok {
								if srv, err := sftp.NewServer(ch, sftp.ReadOnly()); err == nil {
									_ = srv.Serve()
								}
								return
							}
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return dir, ln.Addr().(*net.TCPAddr).Port, ssh.FingerprintSHA256(hk.PublicKey())
}

func TestSync_SFTPFeedReadsTheFileAuditsItsDigestAndHidesTheCredential(t *testing.T) {
	r := newRig(t)
	dir, port, fp := startSFTP(t)
	csv := "worker_id,name,email,sponsor_email,end_date\nC-1,Casey,casey@agency.example,dana@corp.example," +
		now.AddDate(0, 0, 60).Format("2006-01-02") + "\n"
	if err := os.WriteFile(dir+"/c.csv", []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := func(hostKey string) string {
		return `{"sftp":{"host":"127.0.0.1","port":` + itoa(port) + `,"path":"` + dir + `/c.csv","username":"feeds","host_key":"` + hostKey + `","auth":"password"}}`
	}
	r.addSource("sf", store.VmsCSV, "", settings(fp), sftpPW)

	// the stored credential is sealed, not the password
	if enc := r.source("sf").CredentialEnc; len(enc) == 0 || strings.Contains(string(enc), sftpPW) {
		t.Fatalf("credential_enc = %q", enc)
	}
	reps, err := r.svc.Sync(r.ctx, r.f.B.ID)
	if err != nil || len(reps) != 1 {
		t.Fatalf("Sync = %+v, %v", reps, err)
	}
	sum := sha256.Sum256([]byte(csv))
	want := hex.EncodeToString(sum[:])
	rep := reps[0]
	if rep.Status != vms.StatusOK || rep.Records != 1 || rep.Applied["created"] != 1 || rep.FileSHA256 != want || rep.FileBytes != len(csv) {
		t.Fatalf("report = %+v", rep)
	}
	if got := contractors(t, r)["vms-csv-C-1"]; got == nil {
		t.Fatalf("contractors = %v", contractors(t, r))
	}
	var detail string
	r.do(func(c *store.TenantTx) error {
		evs, err := c.AuditEvents(store.AuditFilter{Action: "vms.sync"})
		if err != nil || len(evs) == 0 {
			t.Fatalf("audit = %d, %v", len(evs), err)
		}
		detail = string(evs[0].Detail)
		return nil
	})
	if !strings.Contains(detail, want) || strings.Contains(detail, sftpPW) {
		t.Errorf("audit detail = %s", detail)
	}

	// a different host key is refused, the feed fails, nothing leaks, and the watermark stays
	r.addSource("pinned-wrong", store.VmsCSV, "", settings("SHA256:"+strings.Repeat("A", 43)), sftpPW)
	reps, _ = r.svc.Sync(r.ctx, r.f.B.ID, "pinned-wrong")
	if reps[0].Status != vms.StatusFailed || !strings.Contains(reps[0].Error, "host key") || strings.Contains(reps[0].Error, sftpPW) {
		t.Errorf("wrong host key: %+v", reps[0])
	}
	if reps[0].FileSHA256 != "" {
		t.Errorf("a refused read has a digest: %+v", reps[0])
	}

	// a wrong password fails without echoing either password
	r.addSource("badpw", store.VmsCSV, "", settings(fp), "not-"+sftpPW)
	reps, _ = r.svc.Sync(r.ctx, r.f.B.ID, "badpw")
	if reps[0].Status != vms.StatusFailed || strings.Contains(reps[0].Error, sftpPW) {
		t.Errorf("wrong password: %+v", reps[0])
	}

	// in production the loopback server is out of bounds
	r.svc.RT = connsync.Runtime{Env: "prod"}
	reps, _ = r.svc.Sync(r.ctx, r.f.B.ID, "sf")
	if reps[0].Status != vms.StatusFailed || reps[0].FileSHA256 != "" {
		t.Errorf("prod loopback: %+v", reps[0])
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
