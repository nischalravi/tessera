# High availability on Postgres (draft)

Status: **partly built** (#517): readiness (`schema`, `draining`), graceful shutdown, per-loop leader leases and the per-process state audit below are in. Object-store archive/backups and cloud KEKs follow in the same issue. It depends on Postgres readiness (#18) and follows
backup and restore (#171, `docs/runbooks/disaster-recovery.md`).

## Goal

The service keeps serving through the loss of one API process, one host or one database
node:

- Availability target: 99.9 % monthly.
- RPO 0 for a node failure (synchronous replica) and ≤ 1 h for a region loss (backups).
- RTO ≤ 5 min for a node failure and ≤ 30 min for a region loss.

## Shape

- **API replicas, stateless**, N ≥ 2 behind a load balancer. All of the following state
  is already in the database: sessions, replay caches, rate-limit buckets, cursors and keys.
  What is still per process today is listed under Open questions.
- **Postgres, one primary plus one synchronous standby** (managed service, or Patroni).
  Failover promotes the standby; replicas reconnect through a single writer endpoint.
- **Background loops run on exactly one replica**: the JIT sweeper, key rotation, the
  audit checkpointer, alerts, SIEM, review schedules and backups. They take a Postgres
  advisory lock per loop, so a second replica waits instead of double-running. The audit
  chain needs a single writer per tenant chain head. That is a row lock on
  `audit_chain_heads` inside the event transaction, which Postgres gives us.
- **Backups**: `pg_basebackup` plus WAL archiving to object storage for point-in-time
  recovery, sealed under the KEK. The restore verification of #171 (audit chains, anchors,
  heads) is kept as the gate before a restored database serves.

## Changes it needs

1. Store driver: Postgres behind the same `internal/store` API (#18). The tenant guard
   triggers become Postgres triggers, and SQL constants gain a dialect.
2. Leader election for the background loops (advisory locks), with a health signal per
   loop. **Built** (`internal/leader`, `store.DB.LeaderLocker`): every loop in `serve` runs
   under a session-level `pg_try_advisory_lock(hashtextextended('tessera/leader/<loop>', 0))`
   held on one dedicated connection of the replica. A standby retries every 5 s. If the
   lock connection fails (checked every 5 s) every lease is dropped and the loops stop
   until re-acquired; Postgres frees the locks of a dead session by itself, so a crashed
   replica needs no cleanup. SIGTERM releases them. `/readyz` lists `leaders` (`leader` or
   `standby`; a standby is healthy), `/metrics` has `tessera_loop_leader{loop}` and Admin ->
   Platform health shows the same list. SQLite has no election. The job queue is not
   elected: jobs are leased per job and schedules advance in one transaction with a
   deduplicated enqueue key, so replicas do not double-enqueue; because a job runs on one
   replica, the queue sweepers do not gate `/readyz` on Postgres.
3. A readiness probe that fails while the process cannot reach the primary or holds no
   current schema. **Built** (`/readyz` checks `database`, `schema`, `audit_chain`, `kek`,
   `loops`, `draining`).
4. Rate limiting and the in-memory caches move to the database, or become per replica by
   design (and are documented as such). **Audited** below.

## Per-process state (audit, #517)

Already in the database (shared by all replicas): sessions, login transactions, SAML and
CAS replay and DPoP `jti` replay (`replay` table), queue jobs and schedules, audit chain
heads (row lock), signing keys, cursors.

Per replica by design (safe, with the stated effect):

| State | Where | Effect with N replicas |
| --- | --- | --- |
| Rate limiters (`internal/ratelimit`, per IP, session, tenant, user code) | memory, LRU | the effective limit is up to N times the configured one; a load balancer with client-IP affinity restores it. Set limits per replica. |
| Policy loader cache (`internal/policy`) | memory, reloaded when a file changes | policy files are part of the image; replicas of one release agree. |
| OIDC discovery and JWKS cache (`internal/auth/oidcrp`), tenant name cache | memory, short TTL | a change shows within the TTL on each replica. |
| Per-target limits and circuit breakers of connector calls (`worker.Guard`) | memory | each replica limits its own calls; the worker heartbeat reports them per process. |
| Group provisioning per-provisioner mutex (`provisioning.Service.locks`) | memory | serializes within a replica only; the provisioning loop itself is leader-elected. |

Known gap, not changed here: the guest claim-proof replay memory (`internal/guests/claim`,
`Replays`) is in memory, so a proof replayed against a different replica inside twice the
proof window is not caught by it. Moving it to the `replay` table needs a new `kind` and
schema file; tracked as a follow-up on #517.

## Open questions

- Which in-process state remains: the policy loader cache, the step-up challenge store, and
  any `sync.Map` caches. Each must be safe per replica or move to Postgres.
- Cross-region: is a warm standby region a requirement, or is backup-based recovery enough
  (RTO 30 min)?
- The audit anchor sink on S3 Object Lock (Phase 0 PR14) is a prerequisite for trusting
  restores in production.
