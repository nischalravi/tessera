# API parity fixtures

Golden request/response pairs recorded from the original Python (FastAPI)
backend with `record_python.py`, before it was replaced by the Go server. The
Python backend was removed afterwards; to re-record, check out a commit that still has
`mvp/backend` with the `GET /api/accounts` route (e.g. `aba5abb`) and
run `python record_python.py ../../../backend <out-dir>` from this directory
with the backend's requirements installed.

`internal/api/parity_test.go` replays every fixture, in file order, against a
freshly seeded Go server through `httptest` and requires equal JSON.

## How the recording is made deterministic

* **Seed.** The demo company uses `random.Random(7)`. The Go port
  (`internal/connectors/pyrand.go`) re-implements CPython's Mersenne Twister,
  including `init_by_array` seeding and the exact algorithms behind
  `random()`, `randint()`, `choice()`, `shuffle()` and `uniform()`, so seed 7
  produces the same company, the same usage history and the same timestamps
  (down to the microsecond, including CPython's `timedelta(days=float)`
  rounding).
* **Clock.** The recorder freezes `tessera.timeutil.utcnow` at
  `2026-10-08T09:30:00` (naive UTC) before importing the app. The parity test
  gives the Go server the same frozen clock (`TESSERA_NOW` does the same for a
  manually started server), so every timestamp is compared exactly.
* **One database, one sequence.** Fixtures run in order against a single
  database: reads first, then JIT, review, revoke, HRIS/JML and connector-sync
  mutations, so later fixtures check the effects of earlier ones.

## Running

    cd mvp/server && go test ./internal/api -run TestParity -v

160 fixtures (`001`-`160`); the test logs `parity: N/160 fixtures passed`.

## Normalisation rules (applied to both sides before comparing)

1. **Simulated HRIS event ids.** `sim-evt-<n>-<unix>` becomes
   `sim-evt-<n>-<ts>`. The suffix is `int(naive_utc.timestamp())`, which Python
   evaluates in the host's *local* time zone, so it differs between machines.
2. **Violation diffs.** `violations.resolved` and `violations.introduced`
   (simulate and revoke responses) are sorted by `key`. Python builds them from
   a set difference of string keys, so their order depends on
   `PYTHONHASHSEED` and changes from run to run. The Go server returns them
   sorted by `key`.

3. **Audit ledger ids and hashes.** In audit rows, `event_id` and
   `request_id` values that are UUIDs become `<uuid>`, and `hash` and
   `prev_hash` values (64 hex digits) become `<hash>`. Event ids are random,
   and the hashes cover them; the chain itself is checked by
   `internal/audit` and `internal/store` tests, not here.

Numbers are compared by their JSON spelling, not just by value: Python's
`4.0` (a float read back from the database) and `4` (an unvalidated pydantic
default) are different, and the Go server reproduces both (`ojson.Float`,
`jit.Hours`).

Nothing else is normalised: ids, numbers, timestamps, ordering of every other list and
all error bodies (including FastAPI/pydantic `422` shapes) must match exactly.

## Fixtures changed since the Python recording

* `067-audit`, `068-audit-limit`, `155-audit-final` (Phase 0 PR3, the audit
  ledger). `GET /api/audit` now reads the hash-chained `audit_events`. Each
  row keeps `id, at, actor, action, detail` and adds `event_id, seq,
  actor_type, actor_id, outcome, target, request_id, authn, http, hash,
  prev_hash`. Values that changed on purpose:
  * `id` is the event's per-tenant `seq`. Every API call now also writes an
    `http.request` event, so later domain events have larger ids. The list
    leaves `http.request` events out unless `include_http=true`.
  * Events written during an HTTP request are attributed to the request's
    actor, which was `anonymous` until sign-in landed (PR5; see below). The
    actor the caller supplied (a body `actor`/`approver`/`reviewer`, or a job
    name) was kept in `detail.claimed_actor`, unverified; PR5 removed both.
  * JIT `hours` in `jit.request` details is a string (`"1.5"`, `"2.0"`,
    `"4"`). The ledger refuses floats so every RFC 8785 implementation
    reproduces the event hash.

## Replay as a signed-in principal (Phase 0 PR5)

The fixtures were recorded without authentication. Since PR5 every route
except the public allow-list (`GET /api/health`) needs a session, so
`parity_test.go` signs in once with `authtest.LoginAs` and sends every
request with that session's cookie, an allowed `Origin` and the CSRF token:

* the principal is a platform user of `larkspur` with the `tenant_admin`
  and `policy_admin` roles (together they hold every permission the
  fixtures use), signed in with a phishing-resistant method at the frozen
  time, so every step-up requirement is met;
* its email is `security-oncall@larkspur.example`, the approver the Python
  backend recorded when a request named none, so `decided_by` values are
  unchanged wherever the recording used the default;
* its user id (`00000000-0000-4000-8000-0000000000c1`) and authentication
  context id (`…00c2`) are fixed, so the audit rows of `155-audit-final`
  are reproducible;
* JIT requests (`POST /api/jit/requests`) are sent by a second principal,
  `requester@larkspur.example` (an operator, user id `…00c3`, context
  `…00c4`), because a requester may not approve their own request (403
  `self_approval`) and the fixtures approve the requests they create.

Signing in writes no audit event, so the ledger ids (`id`, `seq`) of the
audit fixtures are the recorded ones.

## Fixtures changed in PR5

Each change follows from the PR5 contract: the actor comes only from the
authenticated principal (the body fields `actor`, `approver` and
`reviewer` are removed, and an unknown body field is a 422 like any
other), and the JIT decision route is split into three routes.

* `099-jit-approve-again`: the request body `{"approver": …}` is removed
  (it would now be refused as an unknown field). The response is unchanged
  (400, the request is not pending).
* `100-jit-deny`: the request body `{"approver": "lead@larkspur.example"}`
  is removed; `decided_by` is now the principal,
  `security-oncall@larkspur.example`, instead of the name the client sent.
* `104-jit-bad-action`: `POST /api/jit/requests/2/escalate` was a 422
  `literal_error` on the `{action}` path parameter. The decision routes are
  now `/approve`, `/deny` and `/revoke` (design §16.2, same URLs), so an
  unknown action is a path that does not exist: 404 `{"detail": "Not Found"}`.
* `107-jit-list-after`: the denied request's `decided_by` follows from
  `100` (`security-oncall@larkspur.example`).
* `120-revoke-apply`: the request body field `"actor": "parity@larkspur.example"`
  is removed. The response is unchanged.
* `155-audit-final`: the domain events written by API calls are
  attributed to the signed-in principal instead of `anonymous`:
  `actor` is its email, `actor_type` is `user`, `actor_id` is its user id,
  and `authn` is the authentication summary (`ctx_id`, `aal` 2, `phr`
  true, `acr` `urn:tessera:acr:phr`, `auth_time`, `auth_age_s` 0).
  `detail.claimed_actor` is gone: the client can no longer claim an actor,
  so there is nothing to keep. The three `jit.request` events written by
  the replay (seq 93, 95, 105) are attributed to the requester
  (`requester@larkspur.example`, `…00c3`, `authn.ctx_id` `…00c4`), the
  other domain events to `security-oncall@larkspur.example`. Events written
  by the seed (`system`) are unchanged, and so are every `id` and `seq`.
* `158-openapi`: the API description follows the contract:
  `RevokeIn.actor` and `ReviewDecisionIn.reviewer` are removed, the
  `DecisionIn` schema is gone, `/api/jit/requests/{request_id}/{action}`
  is replaced by the three decision paths (no request body), and the
  document declares the session cookie as its security scheme
  (`components.securitySchemes.session`, a global `security` requirement,
  and none on `/api/health`).

`067-audit` and `068-audit-limit` list only seed events and are unchanged.

* `153-summary-after-sync`, `154-identities-after-sync` (UAT #134). The recorded
  Python backend let `POST /api/connectors/sync` undo the leaver plan and the
  grant revokes run earlier in the sequence: Marcus Bellweather came back as an
  active identity with his accounts and grants. The Go server now treats
  Tessera-side decisions as authoritative (terminated identities, disabled
  accounts and revoked grants are not reverted, see `revoked_grants`), so after
  the sync the summary keeps the earlier remediation (`human` 58, `terminated` 4,
  fewer grants, effective and unused permissions, violations) and Marcus stays
  terminated, which also changes the order of the identity list.

## Fixtures changed for #137 / #142 (review decisions)

* `114-review-unknown`: `POST /api/reviews/items/99999/decision` for an item
  that does not exist is now 404 (was 400); the body `{"detail": "unknown
  review item"}` is unchanged (part of #142: a missing resource is a 404).
