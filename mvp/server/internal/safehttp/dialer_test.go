package safehttp_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// NewDialer is the address guard of the HTTP client for other protocols (LDAP):
// every address a host resolves to is checked before connecting, and the
// loopback exception is dev only.
func TestNewDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ctx := context.Background()
	prod, err := safehttp.NewDialer(safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := safehttp.NewDialer(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dev(ctx, "tcp", ln.Addr().String()); err != nil {
		t.Errorf("dev dialer to the loopback listener: %v", err)
	} else {
		_ = c.Close()
	}
	for _, addr := range []string{ln.Addr().String(), "10.0.0.1:389", "169.254.169.254:80", "[::1]:389", "192.168.1.5:636", "100.100.100.200:80", "[fd00:ec2::254]:80"} {
		if c, err := prod(ctx, "tcp", addr); !errors.Is(err, safehttp.ErrBlockedAddress) {
			if c != nil {
				_ = c.Close()
			}
			t.Errorf("production dialer to %s = %v, want ErrBlockedAddress", addr, err)
		}
	}
	// a name that resolves to a blocked address, or to a mix, is refused outright
	r := dns(map[string][][]string{"ldap.corp.example": {{"203.0.113.9"}}, "rebind.example": {{"8.8.8.8", "10.1.2.3"}}})
	guarded, err := safehttp.NewDialer(safehttp.Options{Env: config.Prod, Resolver: r})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"ldap.corp.example:389", "rebind.example:389"} {
		if _, err := guarded(ctx, "tcp", host); !errors.Is(err, safehttp.ErrBlockedAddress) {
			t.Errorf("dial %s = %v, want ErrBlockedAddress", host, err)
		}
	}
	if _, err := guarded(ctx, "tcp", "nowhere.example:389"); err == nil || strings.Contains(err.Error(), "blocked") {
		t.Errorf("an unresolvable host: %v", err)
	}
	// the loopback exception cannot be had in production
	if _, err := safehttp.NewDialer(safehttp.Options{Env: config.Prod, AllowLoopback: true}); err == nil {
		t.Error("NewDialer accepted the loopback exception in production")
	}
	if _, err := safehttp.NewDialer(safehttp.Options{Env: "staging"}); err == nil {
		t.Error("NewDialer accepted an unknown environment")
	}
}
