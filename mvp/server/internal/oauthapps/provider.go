package oauthapps

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
)

// Provider reads one provider's apps and grants and revokes a grant there. It
// is built from the credential of identity containment, so the same token, base
// URL and safehttp client serve the kill switch and this inventory.
type Provider interface {
	// Read lists every app and grant. It is read-only and complete, or it
	// returns an error and no snapshot.
	Read(ctx context.Context) (*Snapshot, error)
	// RevokeGrant revokes one grant of the app with this client id. It is
	// idempotent: a grant that is already gone is not an error. A grant no
	// API can revoke returns a *ManualError.
	RevokeGrant(ctx context.Context, clientID string, g Grant) error
	// Present re-reads the provider and reports whether the grant still exists.
	Present(ctx context.Context, clientID string, g Grant) (bool, error)
}

// CredentialRemover is a Provider that can also remove a secret or certificate
// of an app (only Entra today; for the others removal is a manual task).
type CredentialRemover interface {
	// RemoveCredential removes the credential; a credential that is already
	// gone is not an error. One no API can remove returns a *ManualError.
	RemoveCredential(ctx context.Context, c Credential) error
	// CredentialPresent re-reads the provider and reports whether the credential still exists.
	CredentialPresent(ctx context.Context, c Credential) (bool, error)
}

// ManualError means no provider API revokes the grant: a person must, and the
// message says how. It is never reported as a success.
type ManualError struct{ Msg string }

func (e *ManualError) Error() string { return e.Msg }

// ErrTooLarge: the provider lists more users or pages than one read follows. A
// partial read would look like grants that disappeared, so it fails instead.
var ErrTooLarge = errors.New("oauthapps: the provider lists more than one read follows")

// Default API origins (Salesforce has none: the instance URL is required).
const (
	defaultGoogle = "https://admin.googleapis.com"
	defaultEntra  = "https://graph.microsoft.com"
	defaultGitHub = "https://api.github.com"
)

// idRE is what a provider id, a client id or a login may hold; anything else is
// refused before it is put in a path.
var idRE = regexp.MustCompile(`^[A-Za-z0-9._@+:~-]{1,254}$`)

// New returns the Provider for name. hc must come from internal/safehttp.
func New(name string, hc *http.Client, cred containment.Credential, sleep func(context.Context, time.Duration) error) (Provider, error) {
	var def string
	switch name {
	case Google:
		def = defaultGoogle
	case Entra:
		def = defaultEntra
	case Salesforce:
	case GitHub:
		def = defaultGitHub
		if !idRE.MatchString(cred.Org) {
			return nil, errors.New("oauthapps: a GitHub organization is required")
		}
	default:
		return nil, fmt.Errorf("oauthapps: no provider %q", name)
	}
	c, err := containment.NewClient(hc, cred.BaseURL, def, "Bearer", cred.Token, sleep)
	if err != nil {
		return nil, err
	}
	switch name {
	case Google:
		return &googleProv{c}, nil
	case Entra:
		return &entraProv{c: c}, nil
	case Salesforce:
		return &salesforceProv{c}, nil
	}
	return &githubProv{c: c, org: cred.Org}, nil
}

// listPages reads a paged list. next returns the path and query of the page
// after the one just read, or an empty path when it was the last. At most
// MaxPages pages are read.
func listPages[T any](ctx context.Context, c *containment.Client, path string, q url.Values,
	next func(out *T, q url.Values) (string, url.Values, error), each func(*T) error) error {
	for n := 0; ; n++ {
		if n >= MaxPages {
			return ErrTooLarge
		}
		var out T
		if err := c.Do(ctx, http.MethodGet, path, q, nil, &out); err != nil {
			return err
		}
		if err := each(&out); err != nil {
			return err
		}
		np, nq, err := next(&out, q)
		if err != nil {
			return err
		}
		if np == "" {
			return nil
		}
		path, q = np, nq
	}
}

// follow turns a provider's next link into a path and query on the host the
// client calls. A link to another host is refused: the bearer token must not
// leave the configured origin.
func follow(c *containment.Client, link string) (string, url.Values, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", nil, errors.New("oauthapps: unreadable next link")
	}
	if u.IsAbs() && u.Host != c.Host() {
		return "", nil, errors.New("oauthapps: next link names another host")
	}
	p := u.EscapedPath()
	if base := c.BasePath(); base != "" {
		p = strings.TrimPrefix(p, base)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil, errors.New("oauthapps: unreadable next link")
	}
	return p, q, nil
}

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

func later(a, b *time.Time) *time.Time {
	if a == nil || (b != nil && b.After(*a)) {
		return b
	}
	return a
}

// appSet collects apps by client id in first-seen order.
type appSet struct {
	byID  map[string]*App
	order []string
}

func newAppSet() *appSet { return &appSet{byID: map[string]*App{}} }

func (s *appSet) get(provider, clientID, name string) *App {
	a := s.byID[clientID]
	if a == nil {
		a = &App{Provider: provider, ClientID: clientID, Name: name}
		s.byID[clientID] = a
		s.order = append(s.order, clientID)
	}
	return a
}

func (s *appSet) snapshot(provider string, notes ...string) *Snapshot {
	snap := &Snapshot{Provider: provider, Notes: notes}
	for _, id := range s.order {
		a := s.byID[id]
		for i := range a.Grants {
			a.LastUsed = later(a.LastUsed, a.Grants[i].LastUsed)
		}
		snap.Apps = append(snap.Apps, *a)
	}
	return snap
}
