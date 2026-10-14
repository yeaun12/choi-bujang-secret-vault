// Stage 12 / task 1: authenticated, WebAuthn-signed, read-only operational summary.
// Do not expose note bodies, judge identities, device keys, credentials or raw audit rows.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { requireDeviceProof } from '../src/stage11-device-proof.mjs';
import { collectWarRoomEvidence, redactWarRoomLog } from '../src/stage12-war-room.mjs';

let database = null;
let verifyLogin = null;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    throw Error('missing_server_configuration');
  }
  database = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  verifyLogin = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
} catch {
  database = null;
  verifyLogin = null;
}

const json = (body, status = 200) => Response.json(body, {
  status, headers: { 'Cache-Control': 'no-store' },
});

export async function GET(request) {
  let url;
  try { url = new URL(request.url); } catch { return json({ error: 'Invalid route.' }, 404); }
  if (url.pathname !== '/api/war-room' || url.search || url.hash) {
    return json({ error: 'Invalid route.' }, 404);
  }
  if (!database || !verifyLogin) return json({ error: 'Service unavailable.' }, 503);
  const identity = await verifyLogin(request.headers.get('authorization'));
  if (identity?.kind !== 'student') return json({ error: 'Student login required.' }, 401);
  const denied = await requireDeviceProof(request, identity, database);
  if (denied) return denied;
  try {
    const result = await collectWarRoomEvidence(database);
    // Log and response use the SAME result. No private DB record goes to logs.
    console.info(JSON.stringify(redactWarRoomLog(result)));
    return Response.json(result, {status:200,headers:{
      'Cache-Control':'no-store','X-Request-Id':result.requestId }});
  } catch {
    return json({ error: 'Operational evidence unavailable.' }, 503);
  }
}

export async function POST() { return json({ error: 'Method not allowed.' }, 405); }
export async function PUT() { return json({ error: 'Method not allowed.' }, 405); }
export async function DELETE() { return json({ error: 'Method not allowed.' }, 405); }
