# MongoDB to Neon migration runbook

This runbook covers the controlled migration from the legacy BackendApi MongoDB database to PatternYard's Neon database. Never place connection strings, email addresses, password hashes, session tokens, IP addresses, birth dates, or private project content in logs, fixtures, pull requests, or issue comments.

## Safety model

- Rehearse every schema and data operation on an isolated Neon branch.
- Use `patternyard-migrator audit` to record source counts without printing documents.
- Run each collection in dry-run mode before enabling writes.
- Preserve public IDs and bcrypt password hashes; hash bearer and reset tokens before insertion.
- Treat Vercel Blob as authoritative for project binaries and assets.
- Keep MongoDB authoritative until reconciliation and rollback rehearsal pass.

## Rehearsal drumbeat

1. Create a fresh Neon branch from the intended target.
2. Apply the numbered SQL files in `migrations/` to that branch in ascending order.
3. Run `patternyard-migrator audit` and store only collection counts.
4. Run each implemented collection with `migrate <collection> --dry-run`. Account-dependent collections must run in this order: `users`, `accountCustomization`, `loggedIPs`, `followers`, `oauthIDs`, `blocking`, `projects`, then `messages`, `userFeed`, and `reports`. Project metadata intentionally runs after users; its remix links are restored in a second pass after all project rows exist. Communication collections run last because their rows reference accounts and, where applicable, projects.
5. Run the write migration against the isolated branch in the same dependency order. Every collection writes a source count, migrated count, rejected count, and deterministic source-ID checksum to `migration.checkpoints`.
6. Compare source/target counts, relationship coverage, stable IDs, aggregate checksums, and sampled non-sensitive semantics.
7. Resolve every row in `migration.rejections`; rerun to prove idempotency.
8. Exercise the Rust API against the rehearsed database.
9. Delete the rehearsal branch only after evidence is attached to the Architecture tracker.

## Production cutover gate

A single cutover is permitted only when every route family is parity-tested, all migration collections rerun cleanly, the final delta fits the approved maintenance window, and rollback has been rehearsed. Otherwise, use the fixed strangler drumbeat from the approved migration plan and move read-only route families first.

## Production sequence

1. Announce the controlled write freeze.
2. Verify current backups and record source collection counts.
3. Apply the reviewed schema to the production Neon branch.
4. Run the full idempotent migration, then the final delta.
5. Reconcile counts, IDs, relationships, aggregate checksums, and Blob references.
6. Run authentication, project ownership, moderation, email, storage, and captcha smoke tests.
7. Move traffic only after all gates pass.
8. Keep the Express deployment as a bounded rollback target; never add a client-side fallback.
9. End the write freeze and observe error rates and reconciliation counters.

## Rollback

- Route traffic back to Express.
- Make MongoDB authoritative again before accepting writes.
- Retain Neon data for investigation; do not delete or rewrite it during the incident.
- Reconcile any writes accepted after the migration boundary using recorded cutover timestamps and request IDs.
- Record the blocking discrepancy before attempting another cutover.
