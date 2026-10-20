package entra

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// defaultEventWindow is how far back StreamEvents reads when since is nil
// (the sign-in log is kept for 7 to 30 days depending on the license).
const defaultEventWindow = 30 * 24 * time.Hour

type signIn struct {
	Created string `json:"createdDateTime"`
	UserID  string `json:"userId"`
	AppID   string `json:"appId"`
	Status  struct {
		ErrorCode *int `json:"errorCode"`
	} `json:"status"`
}

// StreamEvents yields one UsageRecord per (user, app, day) of successful
// sign-ins from the sign-in log, oldest first, for apps known from the last
// discovery. It needs AuditLog.Read.All and Entra ID P1/P2; a 403 yields
// nothing. One run reads at most maxEventPages pages.
func (c *Connector) StreamEvents(ctx context.Context, since *time.Time, yield func(connectors.Event) error) error {
	from := c.now().Add(-defaultEventWindow)
	if since != nil {
		from = *since
	}
	st := newState()
	users := map[string]*eUser{}
	if s := connsync.StoreFrom(ctx); s != nil {
		if cp, err := s.Load(ctx, System, checkpointName); err == nil && cp != nil && connsync.DecodeState(cp.State, st) == nil {
			users = st.Users
		}
	}
	if len(st.Apps) == 0 {
		return nil // no discovered apps to attribute usage to
	}
	type key struct {
		user, sp string
		day      time.Time
	}
	counts := map[key]int{}
	q := "$filter=" + strings.ReplaceAll(url.QueryEscape("createdDateTime ge "+from.UTC().Format(time.RFC3339)+" and status/errorCode eq 0"), "+", "%20") +
		"&$select=createdDateTime,userId,appId,status&$top=1000&$orderby=createdDateTime"
	pages := 0
	err := connsync.Walk(ctx, c.base, c.graph("/auditLogs/signIns", q), func(ctx context.Context, pageURL string) (string, error) {
		var p page[signIn]
		if _, err := c.api.GetJSON(ctx, pageURL, nil, &p); err != nil {
			return "", err
		}
		for _, e := range p.Value {
			t := parseTime(e.Created)
			sp, ok := st.Apps[strings.ToLower(e.AppID)]
			if t == nil || !ok || !validID(e.UserID) || (e.Status.ErrorCode != nil && *e.Status.ErrorCode != 0) {
				continue
			}
			counts[key{e.UserID, sp, t.Truncate(24 * time.Hour)}]++
		}
		if pages++; pages >= c.maxEventPages {
			return "", nil
		}
		return p.NextLink, nil
	})
	if err != nil {
		if connsync.Status(err) == 403 {
			return nil
		}
		return fmt.Errorf("entra: sign-in log: %w", err)
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
		if a.user != b.user {
			return a.user < b.user
		}
		return a.sp < b.sp
	})
	for _, k := range keys {
		ref := connectors.IdentityRef{}
		if u := users[k.user]; u != nil {
			ref.ExternalID, ref.Email = u.EmployeeID, u.Mail
			if ref.ExternalID == "" {
				ref.ExternalID = "entra:" + u.ID
			}
			if ref.Email == "" && strings.Contains(u.UPN, "@") {
				ref.Email = u.UPN
			}
		}
		acct := connectors.Ref{Kind: "account", System: System, ExternalID: k.user}
		ev := &connectors.UsageRecord{Identity: ref, Permission: connectors.Ref{Kind: "perm", System: System, ExternalID: "app:" + k.sp + ":access"},
			Day: k.day, Count: counts[k], Account: &acct}
		if err := yield(ev); err != nil {
			return err
		}
	}
	return ctx.Err()
}
