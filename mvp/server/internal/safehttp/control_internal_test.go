package safehttp

import (
	"errors"
	"testing"
)

// TestControlHookRechecksSocketAddress: the net.Dialer Control hook, the last
// check before connect, refuses blocked socket addresses on its own.
func TestControlHookRechecksSocketAddress(t *testing.T) {
	prod := &dialer{o: Options{Env: "prod"}}
	dev := &dialer{o: Options{Env: "dev", AllowLoopback: true}}
	for _, addr := range []string{"10.0.0.1:443", "169.254.169.254:80", "[::1]:443", "127.0.0.1:443", "[fd00:ec2::254]:80",
		"[::ffff:10.0.0.1]:443", "not-an-address"} {
		if err := prod.control("tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("prod control(%s) = %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8001", "[::1]:8001", "8.8.8.8:443"} {
		if err := dev.control("tcp", addr, nil); err != nil {
			t.Errorf("dev control(%s) = %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.2:443", "10.0.0.1:443", "169.254.169.254:80"} {
		if err := dev.control("tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("dev control(%s) = %v", addr, err)
		}
	}
}
