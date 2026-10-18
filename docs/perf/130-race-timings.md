# Issue 130: race-suite timings

Timings for `go test -race -count=1` before and after the test-performance work in PR #218. They are copied from the PR body. They were not re-measured for this note.

## Measured timings

| Package | Before | After |
|---|---|---|
| `internal/api` | 474 s | 128 s before the `dev` merge; 156 s after it, because `dev` added auth tests |
| `internal/store` | 130 s | 18.5 s (35.6 s when run alongside `api`) |
| Full `./...` | over 25 min on a loaded machine | about 3 to 3.6 min |

Profile before the change (`-race`): SQLite parse and prepare about 32% of CPU, per-test seeding about 18%, race instrumentation inside SQLite about 40%.

## Commit

- The PR body numbers were taken on a branch based on `dev` f2c5d61.
- The branch was then merged with `dev` d2f6bc4: branch head 25b9224444402b20583ffd53372fc0c40482396a. The `api` figure of 156 s is from after that merge.
- The prepared-statement cache tests in `internal/store/stmt_test.go` were added after these measurements and are not included in them.

## Runner resources

Measured on the agent's machine, not on a CI runner:

- `nproc`: 4
- Memory: 16 GB total (`free -m`: 16093 MB)
- `GOMAXPROCS`: not set, so the default of 4 (`go env GOMAXPROCS` prints nothing).
- `go test -p`: not set, so the default of `GOMAXPROCS`, which is 4 packages in parallel.
- Within a package, tests marked `t.Parallel()` also run up to `GOMAXPROCS` at a time (`-parallel` default).

Other dev and Test instances may have been running on the machine, so the timings carry noise.

## CI timeout

Do not change CI's test timeout (currently 25 minutes) on the strength of these numbers. Change it only after measuring on representative CI runners, with their own core count, memory and load. The timeout is set under `.github/`, which this work does not touch.
