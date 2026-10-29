package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/eval"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/lp"
	"github.com/nischalravi/tessera/mvp/server/internal/notify"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Restore of revoked access on a denial (issue #662, LP-6; design docs/design/least-privilege-loop.md sections 5.2
// and 6.2).
//
//	GET  /api/lp/denial-hook                           whether the receiver credential exists, and the URL to deliver to
//	POST /api/lp/denial-hook                           create or rotate the credential; the secret is shown once (step-up)
//	GET  /api/lp/denials?limit=                        the denial events that named a principal with a revoked grant,
//	                                                   with the restore each led to and its latency
//	POST /public/t/{slug}/lp/denials                   the receiver (no session; bearer secret): an EventBridge API
//	                                                   destination delivers CloudTrail AccessDenied events here
//
// The customer's EventBridge rule matches CloudTrail events with errorCode AccessDenied or UnauthorizedOperation
// and delivers them through an API destination whose authorization header is "Bearer <secret>". Tessera adds no
// AWS permission. The event is only a trigger: it restores a grant when the principal has a revoked one and the
// denied action is one the revocation removed (the policy documents recorded at the revoke say so). The restore is
// the ordinary one (payload digest checked, AWS write target, verified by re-reading the target), needs no second
// person and is not blocked by a pause. The loop's job (lp_tick) verifies it, so a verified restore follows the
// event by the engine's send time plus up to one lp_tick period (5 minutes), inside the 15-minute SLO. A
// normalized body {source: cloudtrail|idp, event_id, principal, action, time} is accepted too, for an IdP denial.
//
// The secret is kept as a SHA-256 digest, not sealed: it is a random 256-bit value, only ever compared, so a digest
// is enough and nothing needs the key encryption key to read it back.

func (s *Server) registerLPDenialRoutes() {
	G, P := http.MethodGet, http.MethodPost
	s.handle(G, "/api/lp/denial-hook", read, need(auth.PermGraphRead), s.rd(s.lpDenialHookGet))
	s.handle(P, "/api/lp/denial-hook", write, needStepUp(auth.PermLPManage, auth.StepUpPolicy), s.rd(s.lpDenialHookPut))
	s.handle(G, "/api/lp/denials", read, need(auth.PermGraphRead), s.rd(s.lpDenialsList))
	s.handle(P, "/public/t/{slug}/lp/denials", noTenant, publicRoute, s.lpDenialPush)
}

// lpDenialBody caps what the receiver reads.
const lpDenialBody = 64 << 10

type lpDenialHookView struct {
	Configured bool    `json:"configured"`
	URLPath    string  `json:"url_path,omitempty"`
	CreatedAt  *string `json:"created_at,omitempty"`
	RotatedAt  *string `json:"rotated_at,omitempty"`
	// Secret appears once, in the answer that created or rotated it.
	Secret string `json:"secret,omitempty"`
}

func lpDenialPath(slug string) string { return "/public/t/" + slug + "/lp/denials" }

func (s *Server) lpDenialHookGet(r *http.Request, _ *params) (int, any, error) {
	slug, err := s.slugOf(r, store.TxFrom(r.Context()).Tenant())
	if err != nil {
		return 0, nil, err
	}
	h, err := store.TxFrom(r.Context()).LPDenialHook()
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusOK, lpDenialHookView{URLPath: lpDenialPath(slug)}, nil
	} else if err != nil {
		return 0, nil, err
	}
	c, rot := store.RT(h.CreatedAt), store.RT(h.RotatedAt)
	return http.StatusOK, lpDenialHookView{Configured: true, URLPath: lpDenialPath(slug), CreatedAt: &c, RotatedAt: &rot}, nil
}

func (s *Server) lpDenialHookPut(r *http.Request, _ *params) (int, any, error) {
	slug, err := s.slugOf(r, store.TxFrom(r.Context()).Tenant())
	if err != nil {
		return 0, nil, err
	}
	tx := store.TxFrom(r.Context())
	now := s.clock()
	secret := "lpd_" + hex.EncodeToString(seal.RandomBytes(32))
	h := &store.LPDenialHook{SecretSHA256: seal.SHA256Hex([]byte(secret)), CreatedBy: actor(r), CreatedAt: now, RotatedAt: now}
	rotated := false
	if cur, err := tx.LPDenialHook(); err == nil {
		h.CreatedBy, h.CreatedAt, rotated = cur.CreatedBy, cur.CreatedAt, true
	} else if !errors.Is(err, store.ErrNotFound) {
		return 0, nil, err
	}
	if err := tx.PutLPDenialHook(h); err != nil {
		return 0, nil, err
	}
	if err := tx.Audit(now, actor(r), "lp.denial_hook.save", ojson.Object{{Key: "rotated", Value: rotated}}); err != nil {
		return 0, nil, err
	}
	c, rot := store.RT(h.CreatedAt), store.RT(h.RotatedAt)
	return http.StatusCreated, lpDenialHookView{Configured: true, URLPath: lpDenialPath(slug), CreatedAt: &c, RotatedAt: &rot, Secret: secret}, nil
}

type lpDenialView struct {
	ID           string  `json:"id"`
	Source       string  `json:"source"`
	EventID      string  `json:"event_id"`
	Principal    string  `json:"principal"`
	Action       string  `json:"action"`
	Resource     string  `json:"resource,omitempty"`
	OccurredAt   *string `json:"occurred_at,omitempty"`
	ArrivedAt    string  `json:"arrived_at"`
	Outcome      string  `json:"outcome"`
	RevocationID string  `json:"revocation_id,omitempty"`
	Detail       string  `json:"detail,omitempty"`
	// RestoreState is where the restore stands; RestoredAt and LatencySeconds (arrival to verified restore) are
	// set once it is verified, WithinSLO says whether that was inside 15 minutes.
	RestoreState   string  `json:"restore_state,omitempty"`
	RestoredAt     *string `json:"restored_at,omitempty"`
	LatencySeconds *int64  `json:"latency_seconds,omitempty"`
	WithinSLO      *bool   `json:"within_slo,omitempty"`
}

func (s *Server) lpDenialsList(r *http.Request, _ *params) (int, any, error) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			return 0, nil, badRequest("invalid_limit", "limit must be 1 to 500")
		}
		limit = n
	}
	tx := store.TxFrom(r.Context())
	rows, err := tx.LPDenials(limit)
	if err != nil {
		return 0, nil, err
	}
	items := make([]lpDenialView, 0, len(rows))
	for _, d := range rows {
		v := lpDenialView{ID: d.ID, Source: d.Source, EventID: d.EventID, Principal: d.Principal, Action: d.Action, Resource: d.Resource, OccurredAt: lpTime(d.OccurredAt),
			ArrivedAt: store.RT(d.ArrivedAt), Outcome: d.Outcome, RevocationID: d.RevocationID, Detail: d.Detail}
		if d.Outcome == store.LPDenialRestoreRequested {
			x, err := tx.LPRevocation(d.RevocationID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return 0, nil, err
			}
			if x != nil {
				v.RestoreState = x.State
				if x.RestoredAt != nil {
					lat := int64(x.RestoredAt.Sub(d.ArrivedAt).Seconds())
					ok := x.RestoredAt.Sub(d.ArrivedAt) <= lp.RestoreSLO
					v.RestoredAt, v.LatencySeconds, v.WithinSLO = lpTime(x.RestoredAt), &lat, &ok
				}
			}
		}
		items = append(items, v)
	}
	return http.StatusOK, map[string]any{"items": items}, nil
}

// ---------------------------------------------------------------- the receiver

// lpDenialIn is the body: an EventBridge event (detail-type "AWS API Call via CloudTrail") or the normalized form.
type lpDenialIn struct {
	// normalized
	Source    string `json:"source"`
	EventID   string `json:"event_id"`
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	// both: the EventBridge envelope's time or the normalized event time
	Time   string          `json:"time"`
	Detail *lpDenialDetail `json:"detail"`
}

// lpDenialDetail is the CloudTrail record inside the EventBridge event.
type lpDenialDetail struct {
	EventID     string `json:"eventID"`
	EventTime   string `json:"eventTime"`
	EventSource string `json:"eventSource"`
	EventName   string `json:"eventName"`
	ErrorCode   string `json:"errorCode"`
	Resources   []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
	RequestParameters map[string]json.RawMessage `json:"requestParameters"`
	UserIdentity      struct {
		ARN            string `json:"arn"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
}

// resource is the resource ARN the denied call named: the record's resources, or an S3 object or bucket from its
// request parameters. "" when it named none.
func (x *lpDenialDetail) resource(svc string) string {
	for _, r := range x.Resources {
		if r.ARN != "" {
			return r.ARN
		}
	}
	if svc == "s3" {
		if b := lpStr(x.RequestParameters["bucketName"]); b != "" {
			if k := lpStr(x.RequestParameters["key"]); k != "" {
				return "arn:aws:s3:::" + b + "/" + k
			}
			return "arn:aws:s3:::" + b
		}
	}
	return ""
}

var (
	lpDenialActionRE   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}:[A-Za-z0-9_]{1,128}$`)
	lpDenialResourceRE = regexp.MustCompile(`^arn:aws[a-z-]*:[^\s]{1,1000}$`)
	lpDenialEventIDRE  = regexp.MustCompile(`^[A-Za-z0-9._:/=+-]{1,200}$`)
	// a principal a revocation can name: an IAM role, user or group (an assumed-role session maps to its role)
	lpDenialPrincipalRE = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:(role|user|group)/[A-Za-z0-9+=,.@_/-]{1,512}$`)
)

// lpServicePrefix is the IAM prefix of the services whose CloudTrail eventSource host differs from it.
var lpServicePrefix = map[string]string{"monitoring": "cloudwatch", "email": "ses", "runtime.sagemaker": "sagemaker", "tagging": "tag"}

// normalize turns a body into a Denial; ok is false for an event that is not a denial or does not name a grant
// holder (nothing to restore), with the reason.
func (in *lpDenialIn) normalize() (d lp.Denial, ignore string, err error) {
	if in.Detail != nil {
		x := in.Detail
		if !strings.Contains(x.ErrorCode, "AccessDenied") && !strings.Contains(x.ErrorCode, "UnauthorizedOperation") &&
			!strings.Contains(x.ErrorCode, "UnauthorizedAccess") {
			return d, "not_a_denial", nil
		}
		d.Source, d.EventID = store.LPDenialCloudTrail, x.EventID
		d.Principal = x.UserIdentity.SessionContext.SessionIssuer.ARN // an assumed role: the role the grants belong to
		if d.Principal == "" {
			d.Principal = x.UserIdentity.ARN
		}
		svc := strings.TrimSuffix(x.EventSource, ".amazonaws.com")
		if x.EventSource == svc || svc == "" {
			return d, "", badRequest("invalid_event", "detail.eventSource is the service's amazonaws.com host")
		}
		if p, ok := lpServicePrefix[svc]; ok {
			svc = p
		}
		d.Action = svc + ":" + x.EventName
		d.Resource = x.resource(svc)
		in.Time = firstNonEmpty(x.EventTime, in.Time)
	} else {
		d.Source, d.EventID, d.Principal, d.Action, d.Resource = in.Source, in.EventID, in.Principal, in.Action, in.Resource
		if d.Source != store.LPDenialCloudTrail && d.Source != store.LPDenialIdP {
			return d, "", badRequest("invalid_source", "source is cloudtrail or idp")
		}
	}
	switch {
	case !lpDenialEventIDRE.MatchString(d.EventID):
		return d, "", badRequest("invalid_event_id", "the event needs an id of up to 200 characters (CloudTrail's eventID)")
	case !lpDenialActionRE.MatchString(d.Action):
		return d, "", badRequest("invalid_action", "the denied action is service:Action")
	case !lpDenialPrincipalRE.MatchString(d.Principal):
		return d, "no_grant_holder", nil // an assumed role without an issuer, a root user, a service: nothing is revoked for it
	}
	if !lpDenialResourceRE.MatchString(d.Resource) {
		d.Resource = "" // an unusable resource is an unknown one
	}
	if in.Time != "" {
		t, err := time.Parse(time.RFC3339, in.Time)
		if err != nil {
			return d, "", badRequest("invalid_time", "time is RFC 3339")
		}
		d.OccurredAt = &t
	}
	return d, "", nil
}

func lpStr(raw json.RawMessage) string {
	var v string
	_ = json.Unmarshal(raw, &v)
	return v
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// lpDummyDigest stands in for the digest when the tenant has no credential, so the comparison runs either way.
var lpDummyDigest = sha256.Sum256(seal.RandomBytes(32))

func lpDenied() statusBody {
	return statusBody{http.StatusUnauthorized, map[string]any{"error": "unauthorized", "detail": "authentication failed"}}
}

func (s *Server) lpDenialPush(_ http.ResponseWriter, r *http.Request, p *params) (any, error) {
	ctx := r.Context()
	var tenant store.Tenant
	digest, found := "", false
	if slug := p.path["slug"]; store.ValidSlug(slug) {
		err := s.store.ReadSystem(ctx, "lp denial: tenant", func(st *store.SystemTx) error {
			var err error
			tenant, err = st.TenantBySlug(slug)
			return err
		})
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		case tenant.Status == "active" && tenant.ID != tenancy.Platform:
			err := s.store.ReadTenant(ctx, tenant.ID, func(c *store.TenantTx) error {
				h, err := c.LPDenialHook()
				if errors.Is(err, store.ErrNotFound) {
					return nil
				} else if err != nil {
					return err
				}
				digest, found = h.SecretSHA256, true
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	want := lpDummyDigest
	if raw, err := hex.DecodeString(digest); found && err == nil && len(raw) == sha256.Size {
		copy(want[:], raw)
	} else {
		found = false
	}
	token := bearerOf(r)
	got := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || !found || token == "" {
		return lpDenied(), nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, lpDenialBody+1))
	if err != nil || len(raw) > lpDenialBody {
		return nil, badRequest("invalid_body", "the body could not be read or is larger than 64 KiB")
	}
	var in lpDenialIn
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, badRequest("invalid_body", "the body is not a JSON event")
	}
	d, ignore, err := in.normalize()
	if err != nil {
		return nil, err
	}
	if ignore != "" {
		return statusBody{http.StatusAccepted, map[string]any{"outcome": "ignored", "reason": ignore}}, nil
	}
	var res *lp.DenialResult
	err = s.store.InTenant(audit.AsSystem(ctx, lp.ActorDenial), tenant.ID, func(tx *store.TenantTx) error {
		now := s.clock()
		var err error
		if res, err = lp.OnDenial(tx, now, d, lpRemoved, lpExec{s}); err != nil {
			return err
		}
		return s.lpNotifyRestored(tx, now, d, res)
	})
	var le *lp.Error
	switch {
	case errors.Is(err, store.ErrDuplicate):
		return statusBody{http.StatusAccepted, map[string]any{"outcome": lp.OutcomeDuplicate}}, nil // a concurrent redelivery won
	case errors.As(err, &le):
		return nil, lpErr(err)
	case err != nil:
		return nil, err
	}
	return statusBody{http.StatusAccepted, map[string]any{"outcome": res.Outcome, "restored": len(res.Restored)}}, nil
}

// lpNotifyRestored tells the people who manage the loop that access came back and why. (Mapping an AWS principal
// to the owning person needs the ownership of AWS principals, which the tenant does not hold yet.)
func (s *Server) lpNotifyRestored(tx *store.TenantTx, now time.Time, d lp.Denial, res *lp.DenialResult) error {
	if len(res.Restored) == 0 {
		return nil
	}
	to, err := notify.Holders(tx, now, auth.PermLPManage)
	if err != nil {
		return err
	}
	for _, x := range res.Restored {
		subject := "Revoked access is being restored: " + d.Action
		body := "A denial of " + d.Action + " for " + d.Principal + " (" + d.Source + " event " + d.EventID + ") matched access the least-privilege loop revoked. " +
			"The grant " + x.PolicyARN + " is being put back from the payload recorded at the revoke, and will not be proposed again for " +
			strconv.Itoa(lp.ExemptionDays) + " days once the restore is verified."
		if len(body) > notify.MaxBody {
			body = body[:notify.MaxBody]
		}
		if _, err := notify.SecurityAlert(tx, now, "lp.restore:"+x.ID, subject, body, "/least-privilege", to...); err != nil {
			return err
		}
	}
	return nil
}

// lpRemoved says whether revocation r removed the call: an Allow statement of the policy as it was before the revoke
// covers the action on the resource and none of the policy it was replaced with does. A right-size that narrows
// resources keeps the action, so a denial whose resource the event did not name restores only when the action is
// gone from the new document altogether. A change whose prior state cannot be read, or
// whose documents do not parse, confirms nothing, so nothing is restored on it.
func lpRemoved(r *store.LPRevocation, action, resource string) (bool, error) {
	var p lpPayload
	if json.Unmarshal([]byte(r.RestorePayload), &p) != nil || p.Prior == "" {
		return false, nil
	}
	before, ok := lpAllows(p.Prior, action, resource)
	if !ok || !before {
		return false, nil
	}
	if p.Document == "" {
		return true, nil // the change leaves nothing in place (a detach or a delete)
	}
	after, ok := lpAllows(p.Document, action, resource)
	return ok && !after, nil
}

// lpAllows says whether any Allow statement of the document names the action on the resource ("" means any
// resource: the statement's Resource is not weighed; conditions are not weighed: a
// conditional allow may have permitted it). ok is false when the document does not parse.
func lpAllows(doc, action, resource string) (allows, ok bool) {
	res, err := policy.Parse([]byte(doc), policy.Options{Kind: model.PolicyIdentity})
	if err != nil || res == nil || res.Doc == nil || res.Doc.Unparseable != "" {
		return false, false
	}
	for _, st := range res.Doc.Statements {
		if st.Effect != model.EffectAllow {
			continue
		}
		m, err := eval.CompileActions(st.Actions, st.NotActions)
		if err != nil {
			return false, false
		}
		if !m.Match(action) {
			continue
		}
		if resource == "" {
			return true, true
		}
		rm, err := eval.CompileResources(st.Resources, st.NotResources, false)
		if err != nil {
			return false, false
		}
		if rm.Match(resource) {
			return true, true
		}
	}
	return false, true
}
