# Backup, restore and disaster recovery

Issue #171 · checklist row "Support high availability and disaster recovery" (#157).
Code: `mvp/server/internal/backup`, `tessera backup …`, `./run.sh backup|restore`.

## What a backup holds, and what it does not

A backup is an online, transactionally consistent copy of the whole SQLite database
(`VACUUM INTO`): every tenant, sealed secrets, signing keys, the audit ledger and its
checkpoints. It is sealed under the KEK in 1 MiB AES-256-GCM chunks. Each chunk's
authenticated data binds the backup id, the manifest and the chunk position. Any edit,
reorder, truncation or append is detected. The manifest (in clear, no secrets) records the
SHA-256 of the database and every tenant's audit chain head.

Kept **outside** the backup, on purpose. Each needs its own copy:

| Item | Why it is separate | Where to keep it |
|---|---|---|
| **KEK** (`TESSERA_KEK_FILE`) | Without it a backup cannot be opened. Storing it with the backups would defeat the encryption. | Secret manager or HSM escrow, in two places, with access logged. |
| **Audit anchors** (`TESSERA_AUDIT_ANCHOR`) | They prove the database was not rewound. Restore checks the backup against them. | Object storage with write-once retention (prod), or `var/audit-anchors.jsonl` (dev). |
| Policies | Repository files. | Git. |
| Environment / config | Deployment config. | Infrastructure-as-code. |

A backup restored without the matching KEK is refused (`wrong_kek`). Sealed values inside
the database are also bound to that KEK.

## Targets

| | Target | How it is met |
|---|---|---|
| **RPO** (data loss) | ≤ 1 h in production | `TESSERA_BACKUP_EVERY_MINUTES=60` plus an off-host copy at least hourly. The default is 360 (6 h) for dev and test. |
| **RTO** (time to serve again) | ≤ 30 min | Restore is verify-and-rename. The CI drill takes well under a second on the test database, and the demo database (6 MB) about a second. Detection and provisioning a host dominate. |
| Retention | 28 backups (7 days at 6 h; 28 h at 1 h) | `TESSERA_BACKUP_KEEP`. Keep longer copies off-host per your records policy. |

## Set up

1. Give the instance a KEK (`TESSERA_KEK_FILE`); production refuses to start without one.
   Escrow a copy now.
2. Set `TESSERA_BACKUP_DIR` to a directory on a **different volume** from the database.
   `tessera serve` then writes a backup every `TESSERA_BACKUP_EVERY_MINUTES`, keeps the
   newest `TESSERA_BACKUP_KEEP` and records `platform.backup.created` in the platform audit
   chain.
3. Copy backups off the host. Either:
   - sync `TESSERA_BACKUP_DIR` to object storage; or
   - from cron, run `tessera backup create -dir … -upload "<presigned PUT URL>"`. The upload
     goes through the SSRF-guarded client (`internal/safehttp`), so in production it must
     be https to a public address.
4. Check it works: `tessera backup list -dir …`, then `tessera backup verify -in <file>`.

Manual backup at any time, with the server running: `./run.sh backup -dir /backups`
(or `tessera backup create`).

## Restore

1. **Stop the server** (all API processes on this database).
2. Pick the newest backup that is older than the incident:
   `tessera backup list -dir /backups`.
3. Verify it without touching anything:
   `tessera backup verify -in /backups/tessera-….tbak`.
   It prints each tenant's chain check. `newer-anchored-events>=N` means the live anchors
   reach N events past this backup: that much recorded activity will be lost.
4. Restore: `./run.sh restore /backups/tessera-….tbak` (this runs
   `tessera backup restore -force`). The current database is moved aside to
   `<db>.pre-restore-<time>`. Nothing is changed if any check fails.
5. Start the server, then run
   `tessera audit verify -all -anchors <anchor URL>`. It must pass.
6. After a restore, close the gap the backup cannot cover:
   - **Credentials are revoked for you.** Sessions, sign-in transactions, bootstrap codes and
     access tokens that were valid at snapshot time would come back with the backup, and
     revocations made since are lost. So the restore itself revokes every active session
     (reason `restore`), deletes pending sign-ins and unconsumed bootstrap invitations, and
     revokes the `access_token` signing keys (the server mints fresh ones on start). The
     restore report and the `platform.backup.restored` event give the counts. **Users sign in
     again.** Issue new bootstrap codes if a tenant still needs one. `idp_client_auth` keys
     are kept, because they are registered with the IdPs.
   - **Replay protection has a gap.** `replay_cache` entries consumed after the snapshot cannot
     be recovered, so a SAML assertion or DPoP proof seen after the snapshot could be replayed.
     Both windows are short (minutes), so the exposure ends soon after the restore. Where that
     matters, wait out the window before reopening sign-in.
   - **Re-sync connectors** (`POST /api/connectors/sync`) so identities and accounts match
     the source systems again. The JIT sweeper expires anything that lapsed in the gap on
     its first run.
   - Re-apply any configuration changed since the backup (config transport, #170, if used).
7. Record the incident. The restore is recorded as `platform.backup.restored`, with the
   backup id and the anchored events lost.

### When a backup is refused (exit 7)

| Code | Meaning | Action |
|---|---|---|
| `wrong_kek` | The backup was sealed under another KEK. | Use the KEK of the instance that took it. |
| `tampered_backup` | The file or its manifest was changed, truncated or extended. | Use another copy. Treat it as a security incident if the copy was in your custody. |
| `verification_failed` | It decrypts, but an audit chain, checkpoint signature, anchor or chain head does not match. | Use an older backup. Investigate: the database was altered before the backup was taken. |
| `target_exists` | The database exists and `-force` was not given. | Stop the server, then use `./run.sh restore`, which passes `-force`. |

Restoring to a new host: set the same `TESSERA_KEK_FILE` and `TESSERA_AUDIT_ANCHOR` first.
In dev, the auto-generated KEK lives in `var/dev-kek` next to the database, so restore into
the same directory or copy that file along.

## Drill

- **Every CI run**: `TestBackupDRDrill` (`mvp/server/cmd/tessera/backup_test.go`) runs with
  the Go suite. It backs up a live database, deletes it, restores it with the CLI, checks the
  restored chain with `tessera audit verify -all` against the anchors, and checks that a
  tampered backup is refused. `internal/backup` tests cover editing, reordering, truncation,
  a wrong KEK, a broken chain inside the backup, and a foreign anchor source.
- **Quarterly, by a human**: restore the latest production backup to a scratch host (steps
  3 to 5 above). Time it against the RTO, and record the time and the result in the
  evidence log.

## High availability (next)

The current design gives you recovery, not availability: one SQLite file served by one
process. Active/passive HA on Postgres, with stateless API replicas, depends on Postgres
readiness (#18). The draft design is in `docs/design/ha-postgres.md`.
