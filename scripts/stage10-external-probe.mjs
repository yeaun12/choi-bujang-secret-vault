// Independent external-runner diagnostics. GET only; no secrets, writes or judge impersonation.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const config = JSON.parse(readFileSync('aleph.config.json', 'utf8'));
const expected = '89a749e95316235a6957ccbe6b494e0f2866e053';
const errors = [];
async function get(url) {
  try {
    const response = await fetch(url, {
      method: 'GET', redirect: 'manual', cache: 'no-store',
      signal: AbortSignal.timeout(12000), headers: { 'Accept': 'application/json, text/plain;q=0.9, */*;q=0.1' },
    });
    const body = await response.text();
    const ct = response.headers.get('content-type') ?? '';
    return { status: response.status, type: ct, body, vercel: response.headers.get('x-vercel-id') || '' };
  } catch (e) { return { status: null, type: '', body: '', vercel: '', error: e.name + ': ' + e.message }; }
}
function check(label, result, status) {
  console.log(JSON.stringify({ label, status: result.status, expected: status,
    contentType: result.type, vercelRequestId: result.vercel, error: result.error ?? null }));
  if (result.status !== status) errors.push(label + ': expected ' + status + ', got ' + (result.status ?? 'network error'));
}
const primary = config.publicAppUrl;
assert.equal(primary, 'https://choi-bujang-secret-vault-blush.vercel.app');
const primaryConfig = await get(primary + '/aleph.json');
check('alias public deployment identity', primaryConfig, 200);
let descriptor = null;
if (primaryConfig.status === 200) {
  try {
    descriptor = JSON.parse(primaryConfig.body);
    const shape = {
      schema: descriptor.schema, step: descriptor.step, commit: descriptor.commit,
      publicAppUrl: descriptor.publicAppUrl, restoreRoute: descriptor.restoreRoute,
      repoUrl: descriptor.repoUrl, judgeIssuer: descriptor.judgeIssuer,
      restoreListed: descriptor.allowedRoutes?.includes('POST /api/restore') === true,
    };
    console.log('PUBLIC_DESCRIPTOR ' + JSON.stringify(shape));
    if (shape.schema !== 'aleph.defense.deployment.v1' || shape.step !== 10
      || shape.commit !== expected || shape.restoreRoute !== '/api/restore'
      || shape.repoUrl !== config.repoUrl || shape.judgeIssuer !== config.judgeIssuer
      || !shape.restoreListed) errors.push('deployment descriptor mismatch');
  } catch (e) { errors.push('malformed public deployment descriptor: ' + e.message); }
}
let alternate = null;
try {
  const u = new URL(descriptor?.publicAppUrl);
  if (u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash
    && u.pathname === '/' && /^choi-bujang-secret-vault-[a-z0-9-]+\.vercel\.app$/u.test(u.hostname)
    && u.origin !== primary) alternate = u.origin;
  else if (u.origin !== primary) errors.push('untrusted or malformed published deployment URL');
} catch { errors.push('missing or malformed deployment publicAppUrl'); }
for (const [tag, origin] of [['submitted alias', primary], ...(alternate ? [['publicAppUrl deployment hostname', alternate]] : [])]) {
  check(tag + ' GET /', await get(origin + '/'), 200);
  check(tag + ' GET /api/restore (method guard)', await get(origin + '/api/restore'), 405);
  check(tag + ' GET /api/notes (anonymous guard)', await get(origin + '/api/notes'), 401);
  check(tag + ' GET /aleph.json', await get(origin + '/aleph.json'), 200);
}
const jwks = await get(config.judgeIssuer + '/.well-known/jwks.json');
check('official judge JWKS endpoint', jwks, 200);
if (jwks.status === 200) {
  try {
    const j = JSON.parse(jwks.body);
    const summary = { count: Array.isArray(j.keys) ? j.keys.length : null,
      algorithms: Array.isArray(j.keys) ? j.keys.map(k=>k.alg).filter(Boolean) : [] };
    console.log('JUDGE_PUBLIC_JWKS ' + JSON.stringify(summary));
    if (!Array.isArray(j.keys) || !j.keys.length) errors.push('official JWKS has no public keys');
  } catch { errors.push('official JWKS is not JSON'); }
}
console.log('EXTERNAL_PROBE_RESULT ' + JSON.stringify({ pass: errors.length === 0, errors }));
if (errors.length) process.exitCode = 1;
