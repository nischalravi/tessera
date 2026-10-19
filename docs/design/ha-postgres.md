# High availability on Postgres (draft)

Status: **draft for review**. Not built. It depends on Postgres readiness (#18) and follows
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
   loop.
3. A readiness probe that fails while the process cannot reach the primary or holds no
   current schema.
4. Rate limiting and the in-memory caches move to the database, or become per replica by
   design (and are documented as such).

## Open questions

- Which in-process state remains: the policy loader cache, the step-up challenge store, and
  any `sync.Map` caches. Each must be safe per replica or move to Postgres.
- Cross-region: is a warm standby region a requirement, or is backup-based recovery enough
  (RTO 30 min)?
- The audit anchor sink on S3 Object Lock (Phase 0 PR14) is a prerequisite for trusting
  restores in production.
