package safehttp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://hooks.slack.com/services/T0/B0/SECRET": "https://hooks.slack.com/…",
		"https://h.example:8443/x?token=SECRET":         "https://h.example:8443/…",
		"https://h.example?token=SECRET":                "https://h.example/…",
		"https://u:SECRET@h.example/":                   "https://h.example",
		"https://h.example":                             "https://h.example",
		"not a url":                                     "(invalid URL)",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubError(t *testing.T) {
	target := "https://hooks.example/services/T000/B000/SECRETPATH?code=SECRETQUERY"
	inner := fmt.Errorf("redirect to %s refused", target)
	for _, err := range []error{
		&url.Error{Op: "Post", URL: target, Err: errors.New("dial tcp: connection refused")},
		fmt.Errorf("webhook: %w", &url.Error{Op: "Post", URL: target, Err: inner}),
		errors.New("something about B000/SECRETPATH and code=SECRETQUERY"),
	} {
		got := ScrubError(err, target)
		for _, bad := range []string{"SECRETPATH", "SECRETQUERY"} {
			if strings.Contains(got, bad) {
				t.Errorf("ScrubError(%v) = %q leaks %q", err, got, bad)
			}
		}
	}
	got := ScrubError(fmt.Errorf("webhook: %w", &url.Error{Op: "Post", URL: target, Err: errors.New("dial tcp: connection refused")}), target)
	if got != "webhook: Post https://hooks.example/…: dial tcp: connection refused" {
		t.Errorf("url.Error scrubbed to %q", got)
	}
	if ScrubError(nil, target) != "" {
		t.Error("nil error")
	}
}
