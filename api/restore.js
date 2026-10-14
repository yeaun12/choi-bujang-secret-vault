// Stage 10: private one-note recovery. No public note body or bearer token logs.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  isJudgeB, restoreOneJudgeBNote, previewOneJudgeBNote, findSingleChangedJudgeBNote,
  verifyOriginalBackupAudit,
} from '../src/stage10-note-recovery.mjs';
import { stage10Repository } from '../src/stage10-recovery-repository.mjs';
import { runPostRestoreHttpRetests } from '../src/stage10-postrestore-retest.mjs';

let database = null;
let verifyLogin = null;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    throw new Error('missing_server_configuration');
  }
  database = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  verifyLogin = createLoginVerifier({
    config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
  });
} catch {
  database = null;
  verifyLogin = null;
}

const json = (body, status = 200) => Response.json(body, {
  status, headers: { 'Cache-Control': 'no-store' },
});
// Privacy-safe server trace: reason codes only, never tokens or note bodies.
const trace = (stage, code, status) =>
  console.info(JSON.stringify({ stage10_restore: stage, code, status }));

const NOTE_ID_KEYS = ['noteId', 'id', 'note_id', 'memoId'];
const SHA256 = /^[a-f0-9]{64}$/u;

// Accept one optional target note and optional preview/expectation fields.
// Unknown keys never widen the scope: only ONE named note can be restored.
export function parseRestoreBody(body) {
  if (body === null || body === undefined) return {
    noteId: null, preview: false, expectedSha256: null, expectedOwnerId: null,
  };
  if (typeof body !== 'object' || Array.isArray(body)) return null;
  const named = NOTE_ID_KEYS.filter(key => body[key] !== undefined && body[key] !== null);
  const ids = [...new Set(named.map(key => body[key]))];
  if (ids.length > 1 || ids.some(value => typeof value !== 'string')) return null;
  const expectedSha256 = body.contentSha256 ?? body.expectedSha256 ?? body.sha256 ?? null;
  if (expectedSha256 !== null && (typeof expectedSha256 !== 'string'
      || !SHA256.test(expectedSha256.toLowerCase()))) return null;
  const expectedOwnerId = body.ownerId ?? body.owner_id ?? null;
  if (expectedOwnerId !== null && typeof expectedOwnerId !== 'string') return null;
  return {
    noteId: ids[0] ?? null,
    preview: body.dryRun === true || body.preview === true || body.confirm === false,
    expectedSha256: expectedSha256?.toLowerCase() ?? null,
    expectedOwnerId: expectedOwnerId?.toLowerCase() ?? null,
  };
}

// Owner evidence must retain the exact storage value that was verified.
// The token subject is separate metadata, never a substitute for backup.ownerId.
function publicBackup(backup, owner) {
  return { ...backup, subjectId: owner.subject, storageOwnerId: backup.ownerId };
}

function ownerMatches(expected, identity, storageOwnerId) {
  return expected === null || expected === storageOwnerId
    || expected === identity.userId.toLowerCase();
}

export async function POST(request) {
  if (!database || !verifyLogin) return json({ error: 'Service unavailable.' }, 503);
  let url;
  try { url = new URL(request.url); } catch { return json({ error: 'Invalid route.' }, 404); }
  if (url.pathname !== '/api/restore' || url.search || url.hash) {
    return json({ error: 'Invalid route.' }, 404);
  }
  const authorization = request.headers.get('authorization');
  const identity = await verifyLogin(authorization);
  if (!identity) { trace('auth', 'unauthenticated', 401); return json({ error: 'Authentication required.' }, 401); }
  if (!isJudgeB(identity)) { trace('auth', 'not_judge_b', 403); return json({ error: 'Recovery restricted to verified test B.' }, 403); }

  let raw = null;
  try {
    const text = await request.text();
    raw = text.trim() ? JSON.parse(text) : null;
  } catch { trace('body', 'invalid_json', 400); return json({ error: 'Invalid JSON.' }, 400); }
  const input = parseRestoreBody(raw);
  if (!input) { trace('body', 'invalid_body', 400); return json({ error: 'Supply one noteId.' }, 400); }

  try {
    const repository = stage10Repository(database);
    let noteId = input.noteId;
    if (!noteId) {
      noteId = await findSingleChangedJudgeBNote({ identity, repository });
      if (!noteId) { trace('target', 'no_single_changed_note', 400); return json({ error: 'Supply one noteId.' }, 400); }
    }
    // Always preview first: version and changed fields are known before writing.
    const plan = await previewOneJudgeBNote({ identity, noteId, repository });
    if (plan.status !== 200) {
      trace('preview', plan.code, plan.status);
      return json({ error: plan.code, restored: false,
        backup: { verified: false } }, plan.status);
    }
    // Independent trust anchor: a self-consistent snapshot hash is not enough
    // if both the backup body and its stored digest have been altered.
    const creationProof = await verifyOriginalBackupAudit({ identity, noteId, repository });
    if (!creationProof.verified) {
      await repository.appendAudit({
        judge_run_id: identity.runId.toLowerCase(), identity_label: 'b',
        note_id: noteId.toLowerCase(), owner_id: plan.ownerId,
        event_kind: 'restore_rejected', reason_code: 'backup_origin_not_verified',
      });
      trace('backup', 'backup_origin_not_verified', 409);
      return json({ error: 'backup_origin_not_verified', restored: false,
        backup: { verified: false, reason: creationProof.reason } }, 409);
    }
    if ((input.expectedSha256 && input.expectedSha256 !== plan.backup.contentSha256)
        || !ownerMatches(input.expectedOwnerId, identity, plan.ownerId)) {
      trace('preview', 'expectation_mismatch', 409);
      return json({ error: 'expectation_mismatch', restored: false }, 409);
    }
    const owner = { identity: 'b', subject: identity.userId.toLowerCase(),
      storageOwnerId: plan.ownerId };
    if (input.preview) {
      trace('preview', 'ok', 200);
      return json({ preview: true, restored: false, id: plan.noteId, noteId: plan.noteId,
        ownerId: plan.ownerId, owner, backup: publicBackup(plan.backup, owner),
        version: plan.backup.version, changes: plan.changedFields,
        creationAuditVerified: true,
        currentSha256: plan.beforeSha256 });
    }

    // Recheck the independent audit and persisted snapshot directly before
    // the recovery operation. On a changed or missing anchor, do not write.
    const creationProofAgain = await verifyOriginalBackupAudit({ identity, noteId, repository });
    if (!creationProofAgain.verified
        || creationProofAgain.contentSha256 !== creationProof.contentSha256) {
      trace('backup', 'backup_origin_changed', 409);
      return json({ error: 'backup_origin_changed', restored: false,
        backup: { verified: false } }, 409);
    }
    const result = await restoreOneJudgeBNote({ identity, noteId, repository });
    if (result.status !== 200) {
      trace('restore', result.code, result.status);
      return json({ error: result.code, restored: false }, result.status);
    }
    // Once restoreOneJudgeBNote returns 200, the persisted note and backup
    // tuple have already been verified. Later audit/HTTP failures must never
    // retroactively claim that the restoration itself did not happen.
    const match = {
      id: result.noteId === result.backup.noteId,
      ownerId: result.ownerId === result.backup.ownerId,
      contentSha256: result.contentSha256 === result.backup.contentSha256,
    };
    const restoredEvidence = {
      restored: true,
      id: result.noteId, noteId: result.noteId,
      ownerId: result.ownerId, owner,
      contentSha256: result.contentSha256, mode: result.mode,
      version: result.backup.version, changes: result.changedFields,
      previousSha256: result.beforeSha256,
      backup: { ...publicBackup(result.backup, owner),
        creationAuditVerified: true, creationAuditRereadBeforeRestore: true },
      match: { ...match, all: match.id && match.ownerId && match.contentSha256 },
      scope: { restoredNotes: 1, otherNotesTouched: 0, auditPreserved: true },
    };
    let retest;
    try {
      // Real HTTP calls to the fixed production origin, not in-process GETs.
      // An audit write failure means retest evidence is unavailable, even if
      // some HTTP requests completed. Never infer their results or counts.
      retest = await runPostRestoreHttpRetests({
        identity, noteId: result.noteId, expectedSha256: result.contentSha256,
        authorization,
        requestUrl: new URL('/api/restore', config.publicAppUrl).href,
        configuredAppUrl: config.publicAppUrl, repository,
      });
    } catch {
      trace('retest', 'evidence_unavailable', 503);
      return json({
        ...restoredEvidence,
        error: 'retest_evidence_unavailable',
        retestVerified: false,
        retest: { passed: false, complete: false, evidenceUnavailable: true,
          executed: null, passedCount: null, failedCount: null,
          normal: [], forbidden: [], notRun: [], skipped: [] },
        postRestoreRetest: { success: false, evidenceUnavailable: true,
          executed: null, passed: null, failed: null,
          normal: [], forbidden: [], notRun: [] },
        retests: [],
      }, 503);
    }
    trace('retest', retest.passed ? 'passed' : 'failed', retest.passed ? 200 : 503);
    return json({
      ...restoredEvidence,
      retestVerified: retest.passed,
      retest: {
        passed: retest.passed,
        complete: retest.complete,
        executed: retest.executed,
        passedCount: retest.passedCount,
        failedCount: retest.failedCount,
        normal: retest.results.filter(x => x.kind === 'normal'),
        forbidden: retest.results.filter(x => x.kind === 'forbidden'),
        notRun: retest.skipped.map(x => x.check),
        skipped: retest.skipped,
      },
      // Simple, measured summary alongside the detailed response evidence.
      // Never turn a missing response or an unexecuted check into a pass.
      postRestoreRetest: {
        executed: retest.executed,
        passed: retest.passedCount,
        failed: retest.failedCount,
        normal: retest.results.filter(x => x.kind === 'normal')
          .map(x => ({ check: x.check, status: x.status, result: x.result })),
        forbidden: retest.results.filter(x => x.kind === 'forbidden')
          .map(x => ({ check: x.check, status: x.status, result: x.result })),
        notRun: retest.skipped.map(x => x.check),
        success: retest.passed,
      },
      // Only executed HTTP responses are listed as retests.
      retests: retest.results,
    }, retest.passed ? 200 : 503);
  } catch {
    // Never leak backup content or raw database errors to external clients.
    trace('restore', 'unavailable', 503);
    return json({ error: 'Recovery unavailable.', restored: false }, 503);
  }
}
export async function GET() { return json({ error: 'Method not allowed.' }, 405); }
export async function PUT() { return json({ error: 'Method not allowed.' }, 405); }
export async function DELETE() { return json({ error: 'Method not allowed.' }, 405); }
export async function PATCH() { return json({ error: 'Method not allowed.' }, 405); }
