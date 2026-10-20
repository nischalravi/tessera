package okta

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// defaultEventWindow is how far back StreamEvents reads when since is nil
// (Okta keeps the System Log for 90 days).
const defaultEventWindow = 30 * 24 * time.Hour

type logEvent struct {
	Published string `json:"published"`
	Actor     struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId"`
	} `json:"actor"`
	Target []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"target"`
	Outcome struct {
		Result string `json:"result"`
	} `json:"outcome"`
}

// StreamEvents yields one UsageRecord per (user, app, day) of successful app
// sign-ins (user.authentication.sso) from the System Log, oldest first. One run
// reads at most maxEventPages pages of 1000 events; a later run with a later
// since continues. A 403 (okta.logs.read not granted) yields nothing.
func (c *Connector) StreamEvents(ctx context.Context, since *time.Time, yield func(connectors.Event) error) error {
	from := c.now().Add(-defaultEventWindow)
	if since != nil {
		from = *since
	}
	// The snapshot maps Okta user ids to the identity references accounts use.
	users := map[string]*uRec{}
	if s := connsync.StoreFrom(ctx); s != nil {
		if cp, err := s.Load(ctx, System, checkpointName); err == nil && cp != nil {
			st := newState()
			if connsync.DecodeState(cp.State, st) == nil {
				users = st.Users
			}
		}
	}
	type key struct {
		actor, app string
		day        time.Time
	}
	counts := map[key]int{}
	q := url.Values{"since": {from.UTC().Format(time.RFC3339)}, "sortOrder": {"ASCENDING"}, "limit": {"1000"},
		"filter": {`eventType eq "user.authentication.sso"`}}
	pages := 0
	err := connsync.Walk(ctx, c.base, c.path("/api/v1/logs", q), func(ctx context.Context, pageURL string) (string, error) {
		var evs []logEvent
		h, err := c.api.GetJSON(ctx, pageURL, nil, &evs)
		if err != nil {
			return "", err
		}
		for _, e := range evs {
			t := parseTime(e.Published)
			if t == nil || e.Outcome.Result != "SUCCESS" || !validID(e.Actor.ID) {
				continue
			}
			for _, tg := range e.Target {
				if tg.Type == "AppInstance" && validID(tg.ID) {
					counts[key{e.Actor.ID, tg.ID, t.Truncate(24 * time.Hour)}]++
				}
			}
		}
		if pages++; pages >= c.maxEventPages {
			return "", nil
		}
		return nextLink(h), nil
	})
	if err != nil {
		if connsync.Status(err) == 403 {
			return nil
		}
		return fmt.Errorf("okta: system log: %w", err)
	}
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if !a.day.Equal(b.day) {
			return a.day.Before(b.day)
		}
		if a.actor != b.actor {
			return a.actor < b.actor
		}
		return a.app < b.app
	})
	for _, k := range keys {
		ref := connectors.IdentityRef{}
		if u := users[k.actor]; u != nil {
			ref = *u.Acct.Identity
		}
		acct := connectors.Ref{Kind: "account", System: System, ExternalID: k.actor}
		ev := &connectors.UsageRecord{Identity: ref, Permission: connectors.Ref{Kind: "perm", System: System, ExternalID: "app:" + k.app + ":access"},
			Day: k.day, Count: counts[k], Account: &acct}
		if err := yield(ev); err != nil {
			return err
		}
	}
	return ctx.Err()
}
