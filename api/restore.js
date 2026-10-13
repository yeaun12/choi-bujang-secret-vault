// Stage 10: private one-note recovery. No public note body or bearer token logs.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { isJudgeB, restoreOneJudgeBNote } from '../src/stage10-note-recovery.mjs';
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
export async function POST(request) {
  if (!database || !verifyLogin) return json({ error: 'Service unavailable.' }, 503);
  let url;
  try { url = new URL(request.url); } catch { return json({ error: 'Invalid route.' }, 404); }
  if (url.pathname !== '/api/restore' || url.search || url.hash) {
    return json({ error: 'Invalid route.' }, 404);
  }
  const identity = await verifyLogin(request.headers.get('authorization'));
  if (!identity) return json({ error: 'Authentication required.' }, 401);
  if (!isJudgeB(identity)) return json({ error: 'Recovery restricted to verified test B.' }, 403);

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).length !== 1
      || (!Object.hasOwn(body, 'noteId') && !Object.hasOwn(body, 'id'))) {
    return json({ error: 'Supply one noteId.' }, 400);
  }
  const noteId = body.noteId ?? body.id;
  try {
    const repository = stage10Repository(database);
    const result = await restoreOneJudgeBNote({ identity, noteId, repository });
    if (result.status !== 200) return json({ error: result.code }, result.status);
    // These are ACTUAL HTTP requests after the restore; the state must be
    // rechecked through the resource API. The upstream signed bearer is sent
    // ONLY to this same explicitly allowlisted Vercel application host.
    const retest = await runPostRestoreHttpRetests({
      identity, noteId: result.noteId, expectedSha256: result.contentSha256,
      authorization: request.headers.get('authorization'),
      requestUrl: request.url, configuredAppUrl: config.publicAppUrl,
      deploymentHost: process.env.VERCEL_URL, repository,
    });
    if (!retest.passed) {
      return json({ error: 'post_restore_retest_failed', retests: retest.results }, 503);
    }
    return json({
      id: result.noteId, ownerId: result.ownerId,
      contentSha256: result.contentSha256, mode: result.mode,
      retests: retest.results,
    });
  } catch {
    // Never leak backup content or raw database errors to external clients.
    return json({ error: 'Recovery unavailable.' }, 503);
  }
}
export async function GET() { return json({ error: 'Method not allowed.' }, 405); }
export async function PUT() { return json({ error: 'Method not allowed.' }, 405); }
export async function DELETE() { return json({ error: 'Method not allowed.' }, 405); }
export async function PATCH() { return json({ error: 'Method not allowed.' }, 405); }
