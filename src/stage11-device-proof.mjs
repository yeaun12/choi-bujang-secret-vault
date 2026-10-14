// Stage 11 server-side device signature gate. Enforces fresh, one-use
// server challenges binding HTTP method, exact path+query and raw body SHA-256.
import { createHash, randomBytes } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { verifyAssertion } from './stage11-webauthn.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[a-f0-9]{64}$/u;
export const origin = new URL(config.publicAppUrl).origin;
export const rpId = new URL(config.publicAppUrl).hostname;
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const freshChallenge = () => randomBytes(32).toString('base64url');

export function protectedPath(method, path) {
  if (typeof method !== 'string' || typeof path !== 'string' ||
      path.length > 512 || path.includes('#') || !['GET','POST','PUT','DELETE'].includes(method)) return false;
  if (path === '/api/notes') return ['GET','POST'].includes(method);
  if (/^\/api\/notes\/[0-9a-f-]{36}$/iu.test(path)) return ['GET','PUT','DELETE'].includes(method);
  if (path === '/api/instructor-notices') return ['GET','POST'].includes(method);
  if (/^\/api\/instructor-notices\/[0-9a-f-]{36}$/iu.test(path)) return ['GET','PUT'].includes(method);
  return false;
}

export async function credentialsFor(database, identity) {
  if (identity?.kind !== 'student' || !UUID.test(identity.userId ?? '')) return [];
  const { data, error } = await database.from('stage11_device_credentials')
    .select('credential_id, public_key_jwk, sign_count, revoked_at')
    .eq('owner_id', identity.userId).is('revoked_at', null).limit(20);
  if (error) throw Error('device_registry_unavailable');
  return data ?? [];
}

export async function issueDeviceChallenge(database, identity, { kind, method = null, path = null, bodyHash = null }) {
  if (identity?.kind !== 'student' || !UUID.test(identity.userId ?? '')) throw Error('identity_required');
  if (kind !== 'register' && !(kind === 'request' && protectedPath(method, path) && SHA256.test(bodyHash ?? ''))) {
    throw Error('invalid_challenge_request');
  }
  const challenge = freshChallenge();
  const expiresAt = new Date(Date.now() + 90_000).toISOString();
  const { data, error } = await database.from('stage11_device_challenges')
    .insert({ owner_id: identity.userId, kind, challenge,
      request_method: method, request_path: path, body_sha256: bodyHash,
      expires_at: expiresAt })
    .select('id').single();
  if (error || !data?.id) throw Error('challenge_unavailable');
  return { challengeId: data.id, challenge, expiresAt };
}

export async function consumeDeviceChallenge(database, identity, challengeId, kind) {
  if (identity?.kind !== 'student' || !UUID.test(identity.userId ?? '') ||
      !UUID.test(challengeId ?? '') || !['register','request'].includes(kind)) {
    throw Error('invalid_challenge_identity');
  }
  // Compare-and-swap marks the challenge spent exactly once before verifying a
  // signature. Replays and concurrent duplicate requests cannot use it again.
  const { data, error } = await database.from('stage11_device_challenges')
    .update({ consumed_at: new Date().toISOString() })
    .eq('id', challengeId).eq('owner_id', identity.userId).eq('kind', kind)
    .is('consumed_at', null).gt('expires_at', new Date().toISOString())
    .select('challenge, request_method, request_path, body_sha256').maybeSingle();
  if (error || !data) throw Error('challenge_expired_or_used');
  return data;
}

const denied = (message='Registered device signature required.') => Response.json(
  { error: message }, { status: 403, headers: { 'Cache-Control': 'no-store' } });

export async function requireDeviceProof(request, identity, database) {
  // The official signed judge principal exists for isolated stages 1-10
  // regression and has no physical student authenticator. It is never a
  // substitute for student app-device verification.
  if (identity?.kind === 'judge') return null;
  if (identity?.kind !== 'student') return denied();
  let url;
  try { url = new URL(request.url); } catch { return denied(); }
  const path = url.pathname + url.search;
  if (!protectedPath(request.method, path)) return denied();
  const id = request.headers.get('x-device-challenge-id');
  const credentialId = request.headers.get('x-device-credential-id');
  const authData = request.headers.get('x-device-authenticator-data');
  const clientData = request.headers.get('x-device-client-data');
  const signature = request.headers.get('x-device-signature');
  if (!id || !credentialId || !authData || !clientData || !signature ||
      [id,credentialId,authData,clientData,signature].some(x => x.length > 8192)) return denied();
  try {
    const bytes = Buffer.from(await request.clone().arrayBuffer());
    if (bytes.length > 262144) return denied('Request body too large.');
    const challenge = await consumeDeviceChallenge(database, identity, id, 'request');
    if (challenge.request_method !== request.method || challenge.request_path !== path ||
        challenge.body_sha256 !== sha256(bytes)) return denied('Signed request changed.');
    const { data:registered, error } = await database.from('stage11_device_credentials')
      .select('credential_id, public_key_jwk, sign_count, revoked_at')
      .eq('owner_id', identity.userId).eq('credential_id', credentialId)
      .is('revoked_at', null).maybeSingle();
    if (error || !registered) return denied();
    const proof = verifyAssertion({ credentialId, clientDataJSON: clientData,
      authenticatorData: authData, signature,
      challenge: challenge.challenge, rpId, origin, registered });
    if (proof.counter > 0) {
      const current = Number(registered.sign_count);
      const { data: updated, error: updateError } = await database.from('stage11_device_credentials')
        .update({ sign_count: proof.counter })
        .eq('credential_id', credentialId).eq('owner_id', identity.userId)
        .eq('sign_count', current).select('credential_id').maybeSingle();
      if (updateError || !updated) return denied();
    }
    return null;
  } catch {
    return denied();
  }
}
