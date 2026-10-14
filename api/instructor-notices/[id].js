import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { requireDeviceProof } from '../../src/stage11-device-proof.mjs';
import { hasInstructorMembership, noticePath, validPrincipal } from '../../src/instructor-authorization.mjs';

let database, verifyLogin;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) throw new Error('missing_config');
  database = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  verifyLogin = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
} catch { database = null; verifyLogin = null; }

const json = (data, status = 200) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
async function authorize(request) {
  if (!database || !verifyLogin) return { response: json({ error: 'Unavailable.' }, 503) };
  const identity = await verifyLogin(request.headers.get('authorization'));
  if (!validPrincipal(identity)) return { response: json({ error: 'Authentication required.' }, 401) };
  const deviceDenial = await requireDeviceProof(request, identity, database);
  if (deviceDenial) return { response: deviceDenial };
  return { identity };
}
export async function GET(request) {
  const auth = await authorize(request);
  if (auth.response) return auth.response;
  const resource = noticePath(request);
  if (!resource || resource.collection) return json({ error: 'Unknown resource.' }, 404);
  const { data, error } = await database.from('instructor_notices')
    .select('id, title, content').eq('id', resource.id).maybeSingle();
  if (error) return json({ error: 'Notice could not be loaded.' }, 500);
  if (!data) return json({ error: 'Notice not found.' }, 404);
  return json({ id: data.id, title: data.title, body: data.content });
}
export async function PUT(request) {
  const auth = await authorize(request);
  if (auth.response) return auth.response;
  const resource = noticePath(request);
  if (!resource || resource.collection) return json({ error: 'Unknown resource.' }, 404);
  if (!await hasInstructorMembership(database, auth.identity)) return json({ error: 'Resource access denied.' }, 403);
  let input;
  try { input = await request.json(); } catch { return json({ error: 'Invalid JSON.' }, 400) }
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      typeof input.title !== 'string' || typeof input.body !== 'string') {
    return json({ error: 'Invalid notice input.' }, 400);
  }
  const { data, error } = await database.from('instructor_notices').update({
    title: input.title, content: input.body, updated_at: new Date().toISOString(),
  }).eq('id', resource.id).select('id').maybeSingle();
  if (error) return json({ error: 'Notice could not be updated.' }, 500);
  if (!data) return json({ error: 'Notice not found.' }, 404);
  return json({ id: data.id });
}
export async function POST() { return json({ error: 'Method not allowed.' }, 405); }
export async function DELETE() { return json({ error: 'Method not allowed.' }, 405); }
export async function PATCH() { return json({ error: 'Method not allowed.' }, 405); }
