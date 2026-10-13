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
    actor, which is `anonymous` until sign-in lands (PR5). The actor the
    caller supplied (a body `actor`/`approver`/`reviewer`, or a job name) is
    kept in `detail.claimed_actor`, unverified.
  * JIT `hours` in `jit.request` details is a string (`"1.5"`, `"2.0"`,
    `"4"`). The ledger refuses floats so every RFC 8785 implementation
    reproduces the event hash.
* `153-summary-after-sync`, `154-identities-after-sync` (UAT #134). The recorded
  Python backend let `POST /api/connectors/sync` undo the leaver plan and the
  grant revokes run earlier in the sequence: Marcus Bellweather came back as an
  active identity with his accounts and grants. The Go server now treats
  Tessera-side decisions as authoritative (terminated identities, disabled
  accounts and revoked grants are not reverted, see `revoked_grants`), so after
  the sync the summary keeps the earlier remediation (`human` 58, `terminated` 4,
  fewer grants, effective and unused permissions, violations) and Marcus stays
  terminated, which also changes the order of the identity list.
