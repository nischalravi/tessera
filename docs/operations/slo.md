# Operational monitoring and SLOs (issue #303)

Monitoring is separate from the audit ledger: metrics count and time things, the ledger is evidence. Metrics carry no tenant, user, identity or raw-path label; HTTP series are keyed by the registered route pattern, and every metric caps its series count (`obs.MaxSeries`, overflow folds into `other`).

## Endpoints

| Endpoint | Where | Auth | Audited |
|---|---|---|---|
| `GET /metrics` | internal listener `TESSERA_METRICS_ADDR` only | network position | no (not part of the API) |
| `GET /livez` | API listener | none | no |
| `GET /readyz` | API listener | none | no |
| `GET /api/admin/platform-health` | API listener | session, `admin.read` | yes, like all `/api/*` |

**Probes and the audit rule.** Every `/api/*` request is audited; that is unchanged. `/livez` and `/readyz` are answered before the API pipeline, are not routes of the API, and are excluded from the ledger by exact path (`audit.IsProbePath`, GET and HEAD only), exactly as `GET /api/health` already is: they carry no tenant data and are polled every few seconds by every load balancer. `TestDefaultExcluded_OnlyProbes` pins the exclusion list and `TestProbes_NotAudited_APIStillAudited` proves a probe writes nothing while a neighbouring `/api/*` request, an unknown route and `/metrics` on the API listener each write one event. `/metrics` is a separate `http.Server` on a separate socket that serves nothing else, so no proxy in front of the API can expose it.

**Exposure rules** (`internal/config`): dev and test default to `127.0.0.1:9464` (a taken default port is a warning, not fatal); `off` disables it. Production defaults to off; when set it must be a loopback, private or link-local IP literal (never a host name or public address); a wildcard bind needs `TESSERA_METRICS_ALLOW_WILDCARD=true` for containers whose network policy limits the scraper. It may not equal the API address.

**`/readyz`** returns 200 or 503 with the constant shape `{"status":"ok|unavailable","checks":{"audit_chain":..,"database":..,"kek":..,"loops":..}}`, each value `ok` or `fail`, no error text. Checks: database reachable (read transaction), `_platform` audit chain head readable, KEK seals and opens a probe value, no gated background loop without a success for `TESSERA_READY_MAX_LOOP_LAG_SECONDS` (default 300). Results are cached for 2 s. `/livez` checks nothing but the process, so a database outage never restarts the pod.

## Metrics

Names, types and labels are pinned by `mvp/server/internal/obs/testdata/metrics.golden`.

- `tessera_http_requests_total{route,class}`, `tessera_http_request_duration_seconds{route,class}`
- `tessera_audit_writes_total{result}`, `tessera_audit_write_failures_total`
- `tessera_loop_{last_run_timestamp,last_success_timestamp,lag,interval}_seconds{loop}`, `tessera_loop_runs_total{loop,result}`, `tessera_loop_run_duration_seconds{loop}`. Loops: `jit_sweep`, `request_sweep`, `sponsorship_sweep`, `lifecycle_sweep`, `containment_retries`, `admin_change_sweep`, `notifications_outbox`, `audit_checkpoint` (gated by `/readyz`) and `key_rotation` (daily, not gated). There is no readiness or review-scheduler loop yet; register one with `obs.DefaultLoops` when it exists.
- `tessera_db_tx_duration_seconds{kind,outcome}`, `tessera_db_write_lock_wait_seconds`, `tessera_db_busy_total{kind}` (SQLite only), `tessera_db_pool_connections{state}`, `tessera_db_pool_wait_total`, `tessera_db_pool_wait_seconds_total` (both dialects)
- `tessera_login_total{method,result}`
- `tessera_connector_calls_total{connector,op,result}`, `tessera_connector_call_duration_seconds{connector,op}` for containment providers, LDAP probe operations and OIDC discovery
- `tessera_readiness_check_ok{check}`, `tessera_process_start_time_seconds`

Not included yet: queue depth and oldest job age (the notification outbox and containment retries are only visible as loop freshness), and OpenTelemetry tracing (no dependency added; a later change should keep it off by default and send OTLP through `safehttp`).

## SLOs

| SLI | Definition | Target (30 days) |
|---|---|---|
| Login success | `result="success"` over all `tessera_login_total` | 99% |
| API availability | non-5xx over all `tessera_http_requests_total` | 99.9% |
| API latency (p95) | requests under 1 s over all requests | 95% under 1 s |
| Audit-write success | `tessera_audit_writes_total{result="ok"}` over all | 99.9% (a failure is a 503 to the caller) |
| Loop freshness | `tessera_loop_lag_seconds` for gated loops | under 5 min; under 2 days for `key_rotation` |

Login refusals are Tessera-side refusals (unknown tenant, state or claims failures, IdP errors), not wrong passwords: the IdP authenticates.

## Alerts

`deploy/prometheus/tessera-rules.yml` records `tessera:sli_error_ratio:rate{5m,30m,1h,2h,6h,1d,3d}{sli=...}` and alerts on multi-window burn rates: page at 14.4x (1h and 5m) and 6x (6h and 30m); ticket at 3x (1d and 2h) and 1x (3d and 6h). Loop alerts page at 5 minutes of lag. Validate with `promtool check rules deploy/prometheus/tessera-rules.yml`; `go test ./internal/obs` also parses the file and checks every metric it names exists.

## Responding

- **Burn alert**: open Admin -> Platform health, find the failing signal (loops, audit writes, database), then the server log (`request_id` is in every 503).
- **TesseraLoopStale / readiness failing on `loops`**: the loop's last success is old; read the log line `<name> failed`, fix the cause. The pod is out of rotation until a run succeeds.
- **Audit write failures**: reads fail closed with `503 audit_unavailable`; check the database and the audit chain (`tessera audit verify`).
