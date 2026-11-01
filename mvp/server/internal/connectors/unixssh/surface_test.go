package unixssh

import (
	"reflect"
	"testing"
)

// TestNoRawSSHClientIsExported: a *ssh.Client lets its holder call NewSession().Run(anything), which
// bypasses the "only the fixed commands are sent" rule. No exported method of the package's types
// may hand one out (or a *ssh.Session or *ssh.Conn), so the only way to run a command is
// session.run with a constant, and the only other use of a connection is the SFTP subsystem.
func TestNoRawSSHClientIsExported(t *testing.T) {
	const sshPkg = "golang.org/x/crypto/ssh"
	leaks := func(ty reflect.Type) bool {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice {
			ty = ty.Elem()
		}
		return ty.PkgPath() == sshPkg
	}
	for _, v := range []any{&Connector{}, &SFTPConn{}} {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumMethod(); i++ {
			m := rt.Method(i)
			for j := 0; j < m.Type.NumOut(); j++ {
				if leaks(m.Type.Out(j)) {
					t.Errorf("%s.%s returns %s", rt, m.Name, m.Type.Out(j))
				}
			}
		}
		for i := 0; i < rt.Elem().NumField(); i++ {
			if f := rt.Elem().Field(i); f.IsExported() && leaks(f.Type) {
				t.Errorf("%s.%s is a %s", rt.Elem(), f.Name, f.Type)
			}
		}
	}
}
