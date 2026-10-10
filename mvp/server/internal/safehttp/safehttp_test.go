package safehttp_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// fakeDNS maps host names to addresses; calls counts lookups per host.
type fakeDNS struct {
	answers map[string][][]string // per host, the answer for the 1st, 2nd, ... lookup (the last repeats)
	calls   map[string]*atomic.Int32
}

func dns(m map[string][][]string) *fakeDNS {
	f := &fakeDNS{answers: m, calls: map[string]*atomic.Int32{}}
	for h := range m {
		f.calls[h] = &atomic.Int32{}
	}
	return f
}

func (f *fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ans, ok := f.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	i := int(f.calls[host].Add(1)) - 1
	if i >= len(ans) {
		i = len(ans) - 1
	}
	var out []netip.Addr
	for _, s := range ans[i] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func client(t *testing.T, o safehttp.Options) *http.Client {
	t.Helper()
	c, err := safehttp.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func get(c *http.Client, u string) (*safehttp.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return safehttp.Get(ctx, c, u)
}

// tlsServer is an httptest TLS server (on 127.0.0.1; its certificate is
// valid for 127.0.0.1, ::1 and example.com) and a dev loopback client
// options value that trusts it.
func tlsServer(t *testing.T, h http.Handler) (*httptest.Server, safehttp.Options) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	return srv, safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool}
}

func port(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func TestNewRefusesLoopbackOutsideDev(t *testing.T) {
	for _, o := range []safehttp.Options{
		{Env: config.Prod, AllowLoopback: true},
		{Env: "", AllowLoopback: false},
		{Env: "staging"},
	} {
		if _, err := safehttp.New(o); err == nil {
			t.Errorf("New(%+v) succeeded", o)
		}
	}
}

func TestForConfig(t *testing.T) {
	c, err := config.Load(func(k string) string { return map[string]string{"TESSERA_ENV": "dev"}[k] })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := safehttp.ForConfig(c); err != nil {
		t.Error(err)
	}
}

// TestBlocksAddresses: every listed range is refused before any connection,
// in prod and also in dev with the loopback exception on (which permits only
// 127.0.0.1 and ::1).
func TestBlocksAddresses(t *testing.T) {
	blocked := []string{
		"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"127.0.0.2", "127.255.255.255", "0.0.0.0", "0.1.2.3",
		"169.254.169.254", "169.254.0.1", "100.100.100.200", "100.64.0.1", "192.0.0.192", "168.63.129.16",
		"224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
		"192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1",
		"fc00::1", "fd00:ec2::254", "fe80::1", "fec0::1", "ff02::1", "::", "2001:db8::1",
		"::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:127.0.0.1", "::10.0.0.1",
		"64:ff9b::a00:1", "2002:a00:1::1", "2001::1",
	}
	for _, env := range []safehttp.Options{{Env: config.Prod}, {Env: config.Dev, AllowLoopback: true}} {
		c := client(t, env)
		for _, ip := range blocked {
			if env.AllowLoopback && ip == "::ffff:127.0.0.1" {
				continue // the IPv4-mapped form of 127.0.0.1 is 127.0.0.1
			}
			name := fmt.Sprintf("%s/loopback=%t/%s", env.Env, env.AllowLoopback, ip)
			t.Run(name, func(t *testing.T) {
				host := ip
				if strings.Contains(ip, ":") {
					host = "[" + ip + "]"
				}
				_, err := get(c, "https://"+host+"/latest/meta-data/")
				if !errors.Is(err, safehttp.ErrBlockedAddress) {
					t.Errorf("got %v, want ErrBlockedAddress", err)
				}
			})
		}
	}
}

func TestBlockedTable(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "93.184.215.14", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"} {
		if safehttp.Blocked(netip.MustParseAddr(ip)) {
			t.Errorf("public address %s blocked", ip)
		}
	}
}

// TestLoopbackOnlyInDev: [::1] and 127.0.0.1 are blocked unless the dev
// loopback exception is on.
func TestLoopbackOnlyInDev(t *testing.T) {
	srv, devOpts := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	p := port(t, srv)
	for _, o := range []safehttp.Options{{Env: config.Prod, RootCAs: devOpts.RootCAs}, {Env: config.Dev, RootCAs: devOpts.RootCAs}} {
		c := client(t, o)
		for _, u := range []string{srv.URL, "https://[::1]:" + p + "/"} {
			if _, err := get(c, u); !errors.Is(err, safehttp.ErrBlockedAddress) {
				t.Errorf("%s loopback=false %s: %v, want ErrBlockedAddress", o.Env, u, err)
			}
		}
	}
	c := client(t, devOpts)
	resp, err := get(c, srv.URL)
	if err != nil || string(resp.Body) != "ok" {
		t.Fatalf("dev loopback to 127.0.0.1: %v", err)
	}
	// ::1 is allowed by the exception; whether it connects depends on the
	// host, but it must not be refused as a blocked address.
	if _, err := get(c, "https://[::1]:"+p+"/"); errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Errorf("dev loopback refused [::1]: %v", err)
	}
}

// TestChecksAddressesAfterDNS: a host name is judged by the addresses it
// resolves to, at connect time.
func TestChecksAddressesAfterDNS(t *testing.T) {
	cases := map[string][][]string{
		"internal.example": {{"10.1.2.3"}},
		"metadata.example": {{"169.254.169.254"}},
		"mixed.example":    {{"8.8.8.8", "10.0.0.1"}}, // one bad answer refuses the host
		"v6.example":       {{"fd00::1"}},
		"mapped.example":   {{"::ffff:192.168.0.1"}},
	}
	for _, o := range []safehttp.Options{{Env: config.Prod}, {Env: config.Dev, AllowLoopback: true}} {
		o.Resolver = dns(cases)
		c := client(t, o)
		for host := range cases {
			if _, err := get(c, "https://"+host+"/"); !errors.Is(err, safehttp.ErrBlockedAddress) {
				t.Errorf("%s %s: %v, want ErrBlockedAddress", o.Env, host, err)
			}
		}
	}
}

// TestDNSRebinding: the first lookup answers with an allowed address, a later
// one with the metadata address. Every connect re-resolves and re-checks, so
// the second request is refused.
func TestDNSRebinding(t *testing.T) {
	srv, o := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	r := dns(map[string][][]string{"example.com": {{"127.0.0.1"}, {"169.254.169.254"}}})
	o.Resolver = r
	u := "https://example.com:" + port(t, srv) + "/"
	if _, err := get(client(t, o), u); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := get(client(t, o), u); !errors.Is(err, safehttp.ErrBlockedAddress) {
		t.Errorf("rebound request: %v, want ErrBlockedAddress", err)
	}
	if n := r.calls["example.com"].Load(); n != 2 {
		t.Errorf("%d lookups, want 2", n)
	}
}

func TestRedirects(t *testing.T) {
	other, o := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("other")) }))
	otherPort := port(t, other)
	var srvURL string
	srv, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/final":
			_, _ = w.Write([]byte("final"))
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/to-other-port":
			http.Redirect(w, r, "https://127.0.0.1:"+otherPort+"/", http.StatusFound)
		case "/to-example":
			http.Redirect(w, r, "https://example.com:"+otherPort+"/", http.StatusFound)
		case "/to-evil":
			http.Redirect(w, r, "https://evil.example:"+otherPort+"/", http.StatusFound)
		case "/to-metadata":
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/to-http":
			http.Redirect(w, r, strings.Replace(srvURL, "https://", "http://", 1)+"/final", http.StatusFound)
		}
	}))
	srvURL = srv.URL
	o.Resolver = dns(map[string][][]string{"example.com": {{"127.0.0.1"}}, "evil.example": {{"10.0.0.9"}}})
	c := client(t, o)
	if resp, err := get(c, srv.URL+"/same"); err != nil || string(resp.Body) != "final" {
		t.Errorf("same-host redirect: %v", err)
	}
	for path, want := range map[string]error{
		"/to-other-port": safehttp.ErrRedirect, // another host:port
		"/to-example":    safehttp.ErrRedirect, // another host name
		"/to-metadata":   safehttp.ErrRedirect,
		"/to-http":       safehttp.ErrRedirect, // scheme downgrade
		"/loop":          safehttp.ErrRedirect, // too many
	} {
		if _, err := get(c, srv.URL+path); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", path, err, want)
		}
	}
	// An allowed redirect host is followed, and its address is still checked.
	o.AllowedRedirectHosts = []string{"EXAMPLE.com", "evil.example", "169.254.169.254"}
	c = client(t, o)
	if resp, err := get(c, srv.URL+"/to-example"); err != nil || string(resp.Body) != "other" {
		t.Errorf("allowed redirect host: %v", err)
	}
	for _, path := range []string{"/to-evil", "/to-metadata"} {
		if _, err := get(c, srv.URL+path); !errors.Is(err, safehttp.ErrBlockedAddress) {
			t.Errorf("%s with the host allowed: %v, want ErrBlockedAddress", path, err)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	const limit = 1024
	big := bytes.Repeat([]byte("a"), limit+1)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(bytes.Repeat([]byte("z"), 1<<20)) // ~1 KiB compressed, 1 MiB expanded
	_ = zw.Close()
	srv, o := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exact":
			_, _ = w.Write(big[:limit])
		case "/declared":
			_, _ = w.Write(big) // Content-Length set by the server
		case "/chunked":
			for i := 0; i <= limit; i += 100 {
				_, _ = w.Write(big[:100])
				w.(http.Flusher).Flush()
			}
		case "/gzip-bomb":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
		}
	}))
	o.MaxBodyBytes = limit
	c := client(t, o)
	if resp, err := get(c, srv.URL+"/exact"); err != nil || len(resp.Body) != limit {
		t.Errorf("body at the limit: %v", err)
	}
	for _, p := range []string{"/declared", "/chunked", "/gzip-bomb"} {
		if _, err := get(c, srv.URL+p); !errors.Is(err, safehttp.ErrTooLarge) {
			t.Errorf("%s: %v, want ErrTooLarge", p, err)
		}
	}
	// the default limit is 512 KiB
	o.MaxBodyBytes = 0
	srv2, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, safehttp.DefaultMaxBodyBytes+1))
	}))
	if _, err := get(client(t, o), srv2.URL); !errors.Is(err, safehttp.ErrTooLarge) {
		t.Errorf("default limit: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv, o := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer close(release)
	o.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := get(client(t, o), srv.URL); err == nil {
		t.Error("a hanging server did not time out")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("timeout took %v", d)
	}
}

func TestSchemes(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer plain.Close()
	p := strings.TrimPrefix(plain.URL, "http://127.0.0.1:")
	prod := client(t, safehttp.Options{Env: config.Prod})
	devNoLoopback := client(t, safehttp.Options{Env: config.Dev})
	dev := client(t, safehttp.Options{Env: config.Dev, AllowLoopback: true,
		Resolver: dns(map[string][][]string{"localhost": {{"127.0.0.1"}}, "idp.example": {{"8.8.8.8"}}})})
	cases := []struct {
		name string
		c    *http.Client
		url  string
		want error
	}{
		{"prod http", prod, "http://idp.example.com/.well-known/openid-configuration", safehttp.ErrScheme},
		{"prod http loopback", prod, plain.URL, safehttp.ErrScheme},
		{"dev http without the loopback exception", devNoLoopback, plain.URL, safehttp.ErrScheme},
		{"dev http to a public host", dev, "http://idp.example/", safehttp.ErrScheme},
		{"dev http to localhost by name", dev, "http://localhost:" + p + "/", safehttp.ErrScheme},
		{"ftp", prod, "ftp://example.com/x", safehttp.ErrScheme},
		{"file", prod, "file:///etc/passwd", safehttp.ErrScheme},
		{"user info", prod, "https://user:pass@example.com/", safehttp.ErrURL},
		{"no host", prod, "https:///path", safehttp.ErrURL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := get(c.c, c.url); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.url, err, c.want)
			}
		})
	}
	if resp, err := get(dev, plain.URL); err != nil || string(resp.Body) != "ok" {
		t.Errorf("dev http to 127.0.0.1 with the loopback exception: %v", err)
	}
}

func TestIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://10.0.0.1:3128")
	t.Setenv("HTTP_PROXY", "http://10.0.0.1:3128")
	srv, o := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("direct")) }))
	if resp, err := get(client(t, o), srv.URL); err != nil || string(resp.Body) != "direct" {
		t.Errorf("request went through the environment proxy: %v", err)
	}
}
