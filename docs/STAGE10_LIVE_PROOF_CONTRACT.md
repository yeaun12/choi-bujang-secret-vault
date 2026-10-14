# Stage 10 — canonical live recovery evidence contract

This document describes the **current deployed code contract**, not proof that
the official judge has successfully exercised it. Historical experiments in
README.md and docs/STAGE10_VERIFICATION.md are not live judge evidence.

## Discovery and authorization

- Public deployment descriptor: GET `/aleph.json`. Its
  `restoreRoute` is exactly `/api/restore`. The deployment descriptor's
  `publicAppUrl` is its Vercel-generated deployment hostname; the
  checked-in `aleph.config.json.publicAppUrl` is the fixed production alias.
- Restore: `POST /api/restore`, verified ES256 official **judge B** bearer
  token. A, student and anonymous clients cannot restore.
- JSON `{"noteId":"<UUID>"}` identifies precisely one record. Empty JSON
  is accepted **only if exactly one verified B snapshot differs from the
  corresponding current record**. Optional `dryRun:true` requests preview only.
- The deployed route does **not** accept a user-supplied remote retest host.
  Retests target only the fixed HTTPS `aleph.config.json.publicAppUrl`.
- GET `/api/restore` is intentionally 405; anonymous POST to that route is
  401. These anonymous checks prove authorization guards, **not recovery**.

## Pre-attack evidence

The original judge-B `POST /api/notes` creates the new note, private
snapshot and original `backup_created` audit in one atomic DB operation.
For a previously existing B note, the first B-authenticated PUT/DELETE
captures the prior record before mutation. The snapshot is scoped to
the signed judge run, judge B identity, exact note UUID and stored owner
UUID. A snapshot is never fabricated from a deleted or already corrupted
record at restore time.

`POST /api/restore` independently re-reads the snapshot, verifies
its SHA-256 against actual bytes and its original `backup_created` audit
hash, previews the changes, checks both records a second time immediately
before write, and restores a single note. It then re-reads the persisted
record and matches ID, stored owner and SHA-256. A missing or corrupted
pre-incident snapshot stops recovery (404 or 409); it is not counted as a
successful restore.

## Response evidence when restore and HTTP retests succeed

A **HTTP 200** JSON response following an authorized successful restore
has all of these measured properties:

| JSON response path | Evidence |
| --- | --- |
| `restored` | `true` — the note is restored (or already matches) |
| `backup.verified` | `true` — snapshot read-back and hash verified |
| `backup.creationAuditVerified` | `true` — original creation audit matched |
| `backup.creationAuditRereadBeforeRestore` | `true` — audit was checked again |
| `backup.rereadBeforeWrite` | `true` — stored snapshot was reread |
| `backup.noteId`, `backup.ownerId`, `backup.contentSha256` | Original snapshot tuple |
| `id`, `ownerId`, `contentSha256` | Persisted restored record tuple |
| `match.id`, `match.ownerId`, `match.contentSha256`, `match.all` | `true` only when both tuples match |
| `retestVerified`, `retest.passed`, `retest.complete` | `true` only with measured mandatory HTTP checks |
| `retest.normal[]`, `retest.forbidden[]`, `retests[]` | HTTP status and result per **executed** request |
| `postRestoreRetest` | Counts and normal/forbidden measured status summary |
| `scope.restoredNotes`, `scope.otherNotesTouched`, `scope.auditPreserved` | Scope declaration (1, 0, true) |

Expected real HTTP GET retests against deployed note API:

1. Own restored B note: HTTP 200 and note body SHA-256 matches the backup.
2. Same note without a token: HTTP 401.
3. Own note with an unauthorized query parameter: HTTP 400.
4. A non-existent note with B token: HTTP 404.
5. A known A-owned note with B token, **when a verified A fixture exists**:
   HTTP 404. Otherwise `retest.notRun` explicitly names
   `foreign_denied`. No unexecuted test is reported as executed or passed.

If restoration wrote the note but a mandatory live HTTP retest failed,
the endpoint returns **HTTP 503** with `restored:true`,
`retestVerified:false`, failed status details and append-only failure
audit. This is not a success verdict and is not treated as one.

## Limits and interpretation

- Local `npm run test:stage10` exercises the real code and signed **synthetic**
  judge tokens against a test storage implementation; it cannot prove a
  production judge-B run. Local outputs have `scope:local_synthetic`.
- `npm run bundle` uses anonymous deployed HTTP checks and separately
  labeled synthetic checks. It does not perform authenticated official
  judge-B recovery.
- As of the last checked official run, the judge returned
  `UNV_AMBIGUOUS` twice for the same release. This is **neither a pass nor
  a demonstrated failure**. The live response from the official B token
  and the judge's internal decision criteria have not been observed.
- A database snapshot that already lacks its pre-attack source **cannot**
  be certified by a current-state hash. Same-DB audit cannot withstand a
  fully privileged adversary modifying both snapshot and audit.
- No raw note contents, bearer tokens or server secret keys should appear
  in a report, response audit trail, or repository documentation.
