// Stage 10: private one-note recovery. No public note body or bearer token logs.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  isJudgeB, restoreOneJudgeBNote, previewOneJudgeBNote, findSingleChangedJudgeBNote,
} from '../src/stage10-note-recovery.mjs';
import { stage10Repository } from '../src/stage10-recovery-repository.mjs';
import { runPostRestoreHttpRetests } from '../src/stage10-postrestore-retest.mjs';
import { GET as getNoteItem } from './notes/[id].js';

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
        currentSha256: plan.beforeSha256 });
    }

    const result = await restoreOneJudgeBNote({ identity, noteId, repository });
    if (result.status !== 200) {
      trace('restore', result.code, result.status);
      return json({ error: result.code, restored: false }, result.status);
    }
    // Real requests through the deployed note handler (in-process, no token
    // leaves this function). Failures are reported, never rewritten as passes.
    const retest = await runPostRestoreHttpRetests({
      identity, noteId: result.noteId, expectedSha256: result.contentSha256,
      authorization,
      requestUrl: new URL('/api/restore', config.publicAppUrl).href,
      configuredAppUrl: config.publicAppUrl, repository,
      fetchImpl: (target, init) => getNoteItem(new Request(target, init)),
    });
    trace('restore', retest.passed ? 'ok' : 'retest_failed', 200);
    const match = {
      id: result.noteId === result.backup.noteId,
      ownerId: result.ownerId === result.backup.ownerId,
      contentSha256: result.contentSha256 === result.backup.contentSha256,
    };
    return json({
      restored: true, id: result.noteId, noteId: result.noteId,
      ownerId: result.ownerId, owner,
      contentSha256: result.contentSha256, mode: result.mode,
      version: result.backup.version, changes: result.changedFields,
      previousSha256: result.beforeSha256,
      backup: publicBackup(result.backup, owner),
      match: { ...match, all: match.id && match.ownerId && match.contentSha256 },
      scope: { restoredNotes: 1, otherNotesTouched: 0, auditPreserved: true },
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
      // Only executed HTTP responses are listed as retests.
      retests: retest.results,
    });
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
