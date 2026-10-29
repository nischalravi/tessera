package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Config proposals (server issue #721). A machine client never writes configuration: it files a proposal
// (POST /api/v1/proposals/...), which the server answers with 202 and a change id, and a person approves it with a
// step-up sign-in. ProposeAndWait files one and polls it until it is applied, or fails with the URL a person opens.

const (
	// DefaultWaitTimeout is how long a resource waits for a person to approve a proposal.
	DefaultWaitTimeout = 30 * time.Minute
	// DefaultPollInterval is the time between two polls.
	DefaultPollInterval = 5 * time.Second
)

// Change is the server's view of a proposal (GET /proposals/{change_id}).
type Change struct {
	ChangeID string  `json:"change_id"`
	Type     string  `json:"type"`
	Status   string  `json:"status"`
	URL      string  `json:"url"`
	Failure  *string `json:"failure"`
	// ResultID is the id of what an applied proposal made or changed (a role or ruleset id), when the server can tell.
	ResultID *string `json:"result_id"`
}

// ChangeError is a proposal that was not applied: a person refused it (Status rejected), it was withdrawn or expired,
// the applier failed, or nobody approved it before the wait ran out (TimedOut). It carries the URL a person opens.
type ChangeError struct {
	ChangeID string
	URL      string
	Status   string
	Failure  string
	TimedOut bool
	Waited   time.Duration
}

func (e *ChangeError) Error() string {
	switch {
	case e.TimedOut:
		return fmt.Sprintf("the change was proposed but nobody approved it within %s (change %s, status %s). A person with a step-up "+
			"sign-in approves it at %s; it stays pending for 72 hours, and applying again files a new proposal", e.Waited, e.ChangeID, e.Status, e.URL)
	case e.Failure != "":
		return fmt.Sprintf("the change was %s (change %s): %s. See %s", e.Status, e.ChangeID, e.Failure, e.URL)
	default:
		return fmt.Sprintf("the change was %s (change %s). See %s", e.Status, e.ChangeID, e.URL)
	}
}

// ProposeAndWait files body at path (a path under /proposals) and waits for the change to be applied. timeout bounds the
// wait (zero: DefaultWaitTimeout) and interval is the poll period (zero: DefaultPollInterval). On success it returns the
// applied change. Any other end is a *ChangeError, except a transport or API error, which is returned as it is.
func (c *Client) ProposeAndWait(ctx context.Context, path string, body any, timeout, interval time.Duration) (*Change, error) {
	var filed Change
	if err := c.Do(ctx, http.MethodPost, path, body, &filed); err != nil {
		return nil, err
	}
	if filed.ChangeID == "" {
		return nil, fmt.Errorf("the server accepted the proposal but returned no change id")
	}
	return c.WaitForChange(ctx, filed, timeout, interval)
}

// WaitForChange polls a filed proposal until it is applied, ends otherwise, or the wait runs out.
func (c *Client) WaitForChange(ctx context.Context, filed Change, timeout, interval time.Duration) (*Change, error) {
	if timeout <= 0 {
		timeout = DefaultWaitTimeout
	}
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	last := filed
	for {
		var ch Change
		if err := c.Do(ctx, http.MethodGet, "/proposals/"+url.PathEscape(filed.ChangeID), nil, &ch); err != nil {
			return nil, fmt.Errorf("change %s (see %s): %w", filed.ChangeID, filed.URL, err)
		}
		if ch.URL == "" {
			ch.URL = filed.URL
		}
		last = ch
		switch ch.Status {
		case "applied":
			return &ch, nil
		case "pending_approval", "cooling_off":
		default: // rejected, cancelled, expired, failed
			e := &ChangeError{ChangeID: ch.ChangeID, URL: ch.URL, Status: ch.Status}
			if ch.Failure != nil {
				e.Failure = *ch.Failure
			}
			return nil, e
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("change %s (see %s): %w", filed.ChangeID, filed.URL, ctx.Err())
		case <-deadline.C:
			return nil, &ChangeError{ChangeID: last.ChangeID, URL: last.URL, Status: last.Status, TimedOut: true, Waited: timeout}
		case <-tick.C:
		}
	}
}
