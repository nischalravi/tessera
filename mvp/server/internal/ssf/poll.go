package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Poll streams (RFC 8936). Each poll sends the jtis acknowledged since the
// last one, and the errors found in SETs, and asks for events without
// waiting:
//
//	{"ack":[...],"setErrs":{jti:{"err":...,"description":...}},"returnImmediately":true,"maxEvents":N}
//
// A jti is acknowledged only once its event row is committed (processed,
// unmatched, ignored, or failed with a retry task queued): what is merely
// received, or hit an internal error, is left unacknowledged, so the
// transmitter delivers it again. Acks and errors wait in the transmitter's
// row (pending_acks, pending_errs) until a poll that carries them succeeds.

const (
	pollMaxEvents  = 25
	pollMaxRounds  = 4 // more_available is followed this many times per sweep
	maxPendingAcks = 1000
)

type pollResponse struct {
	Sets      map[string]json.RawMessage `json:"sets"`
	More      bool                       `json:"moreAvailable"`
	setsCount int
}

// PollResult is what one poll of a transmitter did.
type PollResult struct {
	Received int // SETs the transmitter returned
	Acked    int // jtis queued for acknowledgement
	Errors   int // SETs reported back in setErrs
}

// PollAll polls every enabled poll stream of every active tenant. An error in
// one stream is returned after the others ran.
func (s *Service) PollAll(ctx context.Context, db *store.DB) error {
	tenants, err := db.ActiveTenants(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		var ids []string
		if err := db.ReadTenant(ctx, t.ID, func(c *store.TenantTx) error {
			xs, err := c.SSFTransmitters()
			for _, x := range xs {
				if x.Delivery == store.SSFPoll && x.Status == store.SSFEnabled {
					ids = append(ids, x.ID)
				}
			}
			return err
		}); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", t.Slug, err))
			continue
		}
		for _, id := range ids {
			if _, err := s.Poll(ctx, db, t.ID, id); err != nil && ctx.Err() == nil {
				errs = append(errs, fmt.Errorf("tenant %s: transmitter %s: %w", t.Slug, id, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Poll polls one stream: up to pollMaxRounds requests while the transmitter
// reports more events.
func (s *Service) Poll(ctx context.Context, db *store.DB, tenant tenancy.ID, id string) (PollResult, error) {
	var total PollResult
	for round := 0; round < pollMaxRounds; round++ {
		res, more, err := s.pollOnce(ctx, db, tenant, id)
		total.Received += res.Received
		total.Acked += res.Acked
		total.Errors += res.Errors
		if err != nil || !more {
			return total, err
		}
	}
	return total, nil
}

func (s *Service) pollOnce(ctx context.Context, db *store.DB, tenant tenancy.ID, id string) (PollResult, bool, error) {
	var res PollResult
	var tr *store.SSFTransmitter
	var token string
	if err := db.ReadTenant(ctx, tenant, func(c *store.TenantTx) error {
		var err error
		if tr, err = c.SSFTransmitter(id); err != nil {
			return err
		}
		token, err = s.open(tenant, tr.ID, "secret_enc", tr.SecretEnc)
		return err
	}); err != nil {
		return res, false, err
	}
	if tr.Delivery != store.SSFPoll || tr.Status != store.SSFEnabled || tr.PollURL == "" {
		return res, false, errors.New("the transmitter is not an enabled poll stream")
	}
	acks, errs := pendingOf(tr)
	req := map[string]any{"ack": acks, "returnImmediately": true, "maxEvents": pollMaxEvents}
	if len(errs) > 0 {
		req["setErrs"] = errs
	}
	status, raw, err := s.do(ctx, http.MethodPost, tr.PollURL, token, req, 4<<20)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("the poll endpoint answered %d", status)
	}
	var out pollResponse
	if err == nil {
		if jerr := json.Unmarshal(raw, &out); jerr != nil {
			err = errors.New("the poll endpoint's answer is not valid JSON")
		}
	}
	if err != nil {
		s.noteError(ctx, db, tenant, tr.ID, "poll failed: "+err.Error())
		return res, false, err
	}
	// the acks and errors this request carried are delivered: forget exactly those
	if err := db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
		cur, err := c.SSFTransmitter(tr.ID)
		if err != nil {
			return err
		}
		a, e := pendingOf(cur)
		a = slices.DeleteFunc(a, func(j string) bool { return slices.Contains(acks, j) })
		for j := range errs {
			delete(e, j)
		}
		return savePending(c, cur.ID, a, e, s.now())
	}); err != nil {
		return res, false, err
	}
	res.Received = len(out.Sets)
	jtis := make([]string, 0, len(out.Sets))
	for j := range out.Sets {
		jtis = append(jtis, j)
	}
	slices.Sort(jtis)
	newAcks, newErrs := []string{}, map[string]*Error{}
	var internal []error
	for _, jti := range jtis {
		var setStr string
		if err := json.Unmarshal(out.Sets[jti], &setStr); err != nil {
			newErrs[jti] = invalid("the SET is not a string")
			continue
		}
		_, err := s.Receive(ctx, db, tenant, tr, store.SSFPoll, setStr, jti)
		var perr *Error
		switch {
		case err == nil:
			newAcks = append(newAcks, jti)
		case errors.As(err, &perr):
			newErrs[jti] = perr
		default:
			internal = append(internal, fmt.Errorf("jti %s: %w", jti, err)) // not acknowledged: delivered again
		}
	}
	res.Acked, res.Errors = len(newAcks), len(newErrs)
	if len(newAcks) > 0 || len(newErrs) > 0 {
		if err := db.InTenant(ctx, tenant, func(c *store.TenantTx) error {
			cur, err := c.SSFTransmitter(tr.ID)
			if err != nil {
				return err
			}
			a, e := pendingOf(cur)
			a = append(a, newAcks...)
			if len(a) > maxPendingAcks {
				a = a[len(a)-maxPendingAcks:]
			}
			for j, pe := range newErrs {
				e[j] = pe
			}
			return savePending(c, cur.ID, a, e, s.now())
		}); err != nil {
			return res, false, err
		}
	}
	more := out.More && len(internal) == 0 && len(out.Sets) > 0
	return res, more, errors.Join(internal...)
}

func pendingOf(x *store.SSFTransmitter) ([]string, map[string]*Error) {
	acks := []string{}
	errs := map[string]*Error{}
	_ = json.Unmarshal([]byte(x.PendingAcks), &acks)
	_ = json.Unmarshal([]byte(x.PendingErrs), &errs)
	if acks == nil {
		acks = []string{}
	}
	if errs == nil {
		errs = map[string]*Error{}
	}
	return acks, errs
}

func savePending(c *store.TenantTx, id string, acks []string, errs map[string]*Error, now time.Time) error {
	a, err := json.Marshal(acks)
	if err != nil {
		return err
	}
	e, err := json.Marshal(errs)
	if err != nil {
		return err
	}
	return c.SetSSFPollState(id, string(a), string(e), now)
}
