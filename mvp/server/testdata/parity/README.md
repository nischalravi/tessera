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

Numbers are compared by their JSON spelling, not just by value: Python's
`4.0` (a float read back from the database) and `4` (an unvalidated pydantic
default) are different, and the Go server reproduces both (`ojson.Float`,
`jit.Hours`).

Nothing else is normalised: ids, numbers, timestamps, ordering of every other list and
all error bodies (including FastAPI/pydantic `422` shapes) must match exactly.
