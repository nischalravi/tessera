package unixssh

import "testing"

// Fake is a running fake host for the external tests (governed_test.go): the commands the connector
// is expected to send, with their canned output.
type Fake struct {
	Port        string
	Fingerprint string
	KeyPEM      string
	Seen        func() []string
}

// StartFake starts the in-process SSH server. Replies are keyed by the exact command.
func StartFake(t testing.TB, outputs map[string]string) Fake {
	t.Helper()
	signer, pem := newKey(t)
	rep := map[string]fakeReply{}
	for k, v := range outputs {
		rep[k] = fakeReply{out: v}
	}
	h := startHost(t, signer.PublicKey(), rep)
	return Fake{Port: h.portString(), Fingerprint: h.fingerprint(), KeyPEM: pem, Seen: h.seen}
}

// The fixed commands and the canned data of the tests.
const (
	CmdPasswd  = cmdPasswd
	CmdGroup   = cmdGroup
	CmdSudoers = cmdSudoers
	CmdLastlog = cmdLastlog
	PasswdOut  = passwdOut
	GroupOut   = groupOut
	SudoersOut = sudoersOut
	LastlogOut = lastlogOut
)
