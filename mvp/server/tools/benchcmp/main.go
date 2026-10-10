// Command benchcmp measures a running Tessera server end to end: seed time,
// startup time (process start to first healthy response), per-route latency
// (p50/p95 over sequential requests) and resident memory after the run.
//
// It always measures the Go server; pass -python and -py-backend to measure
// the original Python backend (from a checkout of a commit that still has
// mvp/backend) the same way:
//
//	go run ./tools/benchcmp -go-bin ./tessera
//	go run ./tools/benchcmp -go-bin ./tessera -python /path/to/venv/bin/python -py-backend /path/to/mvp/backend
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var routes = []string{
	"/api/health",
	"/api/summary",
	"/api/identities",
	"/api/identities/5",
	"/api/graph?identity_id=5",
	"/api/violations",
	"/api/least-privilege/recommendations",
	"/api/nhi",
}

type result struct {
	name    string
	seed    time.Duration
	startup time.Duration
	p50     map[string]time.Duration
	p95     map[string]time.Duration
	rssKB   int
}

type target struct {
	name  string
	dir   string // working directory
	seed  []string
	serve []string
	env   []string
}

func main() {
	goBin := flag.String("go-bin", "", "path to the built tessera binary (required)")
	python := flag.String("python", "", "python interpreter with the backend's requirements installed")
	pyBackend := flag.String("py-backend", "", "path to an mvp/backend checkout")
	n := flag.Int("n", 50, "requests per route")
	port := flag.Int("port", 8100, "first port to use")
	flag.Parse()
	if *goBin == "" {
		fmt.Fprintln(os.Stderr, "benchcmp: -go-bin is required")
		os.Exit(2)
	}
	tmp, err := os.MkdirTemp("", "tessera-bench-")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(tmp)

	bin, err := filepath.Abs(*goBin)
	if err != nil {
		fail(err)
	}
	goDB := filepath.Join(tmp, "go.db")
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	targets := []target{{name: "Go", dir: tmp,
		seed:  []string{bin, "seed", "-db", goDB},
		serve: []string{bin, "serve", "-addr", addr, "-db", goDB}}}
	if *python != "" && *pyBackend != "" {
		pyDB := "sqlite:///" + filepath.Join(tmp, "py.db")
		targets = append(targets, target{name: "Python", dir: *pyBackend,
			seed:  []string{*python, "-m", "tessera.seed"},
			serve: []string{*python, "-m", "uvicorn", "tessera.api.app:app", "--host", "127.0.0.1", "--port", strconv.Itoa(*port + 1), "--log-level", "warning"},
			env:   []string{"TESSERA_DB=" + pyDB}})
	}
	var results []result
	for i, t := range targets {
		base := fmt.Sprintf("http://127.0.0.1:%d", *port+i)
		r, err := measure(t, base, *n)
		if err != nil {
			fail(fmt.Errorf("%s: %w", t.name, err))
		}
		results = append(results, r)
	}
	report(results)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "benchcmp:", err)
	os.Exit(1)
}

func command(t target, args []string) *exec.Cmd {
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204 -- developer tool running the binaries named on its command line
	cmd.Dir = t.dir
	cmd.Env = append(os.Environ(), t.env...)
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
	return cmd
}

func measure(t target, base string, n int) (result, error) {
	r := result{name: t.name, p50: map[string]time.Duration{}, p95: map[string]time.Duration{}}
	start := time.Now()
	if err := command(t, t.seed).Run(); err != nil {
		return r, fmt.Errorf("seed: %w", err)
	}
	r.seed = time.Since(start)

	srv := command(t, t.serve)
	start = time.Now()
	if err := srv.Start(); err != nil {
		return r, err
	}
	defer func() {
		_ = srv.Process.Signal(syscall.SIGTERM)
		_ = srv.Wait()
	}()
	client := &http.Client{Timeout: 60 * time.Second}
	for {
		if resp, err := client.Get(base + "/api/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Since(start) > 60*time.Second {
			return r, errors.New("server did not become healthy")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.startup = time.Since(start)

	get := func(path string) (time.Duration, error) {
		t0 := time.Now()
		resp, err := client.Get(base + path)
		if err != nil {
			return 0, err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("GET %s: %d", path, resp.StatusCode)
		}
		return time.Since(t0), err
	}
	for _, p := range routes { // warm up
		for range 3 {
			if _, err := get(p); err != nil {
				return r, err
			}
		}
	}
	for _, p := range routes {
		var d []time.Duration
		for range n {
			x, err := get(p)
			if err != nil {
				return r, err
			}
			d = append(d, x)
		}
		slices.Sort(d)
		r.p50[p], r.p95[p] = d[len(d)/2], d[len(d)*95/100]
	}
	r.rssKB, _ = rss(srv.Process.Pid)
	return r, nil
}

func rss(pid int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output() // #nosec G204 -- fixed command, numeric pid
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }

func report(rs []result) {
	head := "| metric |"
	sep := "|---|"
	for _, r := range rs {
		head += " " + r.name + " |"
		sep += "---:|"
	}
	fmt.Println(head)
	fmt.Println(sep)
	row := func(label string, f func(result) string) {
		line := "| " + label + " |"
		for _, r := range rs {
			line += " " + f(r) + " |"
		}
		fmt.Println(line)
	}
	row("seed (demo company)", func(r result) string { return ms(r.seed) })
	row("startup to first healthy response", func(r result) string { return ms(r.startup) })
	row("RSS after run", func(r result) string { return fmt.Sprintf("%.1f MiB", float64(r.rssKB)/1024) })
	for _, p := range routes {
		row("p50 GET "+p, func(r result) string { return ms(r.p50[p]) })
	}
	for _, p := range routes {
		row("p95 GET "+p, func(r result) string { return ms(r.p95[p]) })
	}
}
