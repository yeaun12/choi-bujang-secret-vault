// Stage 11: WebAuthn cryptographic verification. No browser-storage private keys.
// Deliberately supports ES256 / COSE EC2 P-256 and attestation format "none" only.
import { createHash, createPublicKey, verify as verifySignature, timingSafeEqual } from 'node:crypto';

export const base64url = (value) => Buffer.from(value).toString('base64url');
export function decode64(value, max = 8192) {
  if (typeof value !== 'string' || value.length < 1 || value.length > max ||
      !/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error('invalid_encoding');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length === 0 || base64url(bytes) !== value) throw new Error('invalid_encoding');
  return bytes;
}
const sha = bytes => createHash('sha256').update(bytes).digest();
const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(a, b);

function cbor(bytes, start = 0, depth = 0) {
  if (depth > 8 || start >= bytes.length) throw new Error('invalid_cbor');
  let p = start;
  const initial = bytes[p++], type = initial >> 5, detail = initial & 31;
  const len = () => {
    if (detail < 24) return detail;
    if (detail === 24) { if (p + 1 > bytes.length) throw Error('invalid_cbor'); return bytes[p++]; }
    if (detail === 25) { if (p + 2 > bytes.length) throw Error('invalid_cbor'); const n = bytes.readUInt16BE(p); p += 2; return n; }
    if (detail === 26) { if (p + 4 > bytes.length) throw Error('invalid_cbor'); const n = bytes.readUInt32BE(p); p += 4; return n; }
    throw Error('unsupported_cbor_length');
  };
  if (type === 0 || type === 1) { const n = len(); return { value: type === 0 ? n : -1 - n, end: p }; }
  if (type === 2 || type === 3) {
    const n = len();
    if (n > 8192 || p + n > bytes.length) throw Error('invalid_cbor');
    const chunk = bytes.subarray(p, p + n); p += n;
    return { value: type === 2 ? chunk : chunk.toString('utf8'), end: p };
  }
  if (type === 4 || type === 5) {
    const n = len(); if (n > 64) throw Error('invalid_cbor');
    if (type === 4) {
      const out = [];
      for (let i = 0; i < n; i++) { const x = cbor(bytes, p, depth + 1); p = x.end; out.push(x.value); }
      return { value: out, end: p };
    }
    const out = new Map();
    for (let i = 0; i < n; i++) {
      const k = cbor(bytes, p, depth + 1); p = k.end;
      const v = cbor(bytes, p, depth + 1); p = v.end;
      if (out.has(k.value)) throw Error('duplicate_cbor_key');
      out.set(k.value, v.value);
    }
    return { value: out, end: p };
  }
  if (type === 7 && (detail === 20 || detail === 21 || detail === 22)) {
    return { value: detail === 20 ? false : detail === 21 ? true : null, end: p };
  }
  throw new Error('invalid_cbor');
}

function authenticatorData(buffer, rpId, attested) {
  if (buffer.length < 37) throw Error('short_authenticator_data');
  if (!safeEqual(buffer.subarray(0, 32), sha(Buffer.from(rpId)))) throw Error('wrong_rp_id');
  const flags = buffer[32];
  if (!(flags & 0x01) || !(flags & 0x04)) throw Error('user_verification_required');
  if (attested && !(flags & 0x40)) throw Error('credential_data_missing');
  const counter = buffer.readUInt32BE(33);
  return { flags, counter };
}

function clientData(value, type, challenge, origin) {
  const raw = decode64(value);
  let data;
  try { data = JSON.parse(raw.toString('utf8')); } catch { throw Error('invalid_client_data'); }
  if (!data || data.type !== type || data.challenge !== challenge ||
      data.origin !== origin || data.crossOrigin === true) throw Error('client_data_mismatch');
  return raw;
}

export function verifyRegistration({ attestationObject, clientDataJSON, challenge, rpId, origin, credentialId }) {
  const raw = decode64(attestationObject, 15000);
  const parsed = cbor(raw);
  if (parsed.end !== raw.length || !(parsed.value instanceof Map)) throw Error('invalid_attestation');
  const fmt = parsed.value.get('fmt'), statement = parsed.value.get('attStmt');
  const auth = parsed.value.get('authData');
  if (fmt !== 'none' || !(statement instanceof Map) || statement.size !== 0 ||
      !Buffer.isBuffer(auth) || auth.length < 56) throw Error('invalid_attestation');
  clientData(clientDataJSON, 'webauthn.create', challenge, origin);
  const { counter } = authenticatorData(auth, rpId, true);
  const credentialLength = auth.readUInt16BE(53);
  const credentialStart = 55, credentialEnd = credentialStart + credentialLength;
  if (credentialLength < 16 || credentialLength > 1024 ||
      credentialEnd >= auth.length || !safeEqual(auth.subarray(credentialStart, credentialEnd), decode64(credentialId, 2000))) {
    throw Error('credential_id_mismatch');
  }
  const cose = cbor(auth, credentialEnd);
  if (!(cose.value instanceof Map) || cose.end !== auth.length) throw Error('invalid_cose');
  const key = cose.value;
  if (key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1 ||
      !Buffer.isBuffer(key.get(-2)) || key.get(-2).length !== 32 ||
      !Buffer.isBuffer(key.get(-3)) || key.get(-3).length !== 32) throw Error('unsupported_public_key');
  const publicJwk = { kty: 'EC', crv: 'P-256', x: base64url(key.get(-2)),
    y: base64url(key.get(-3)), ext: true, key_ops: ['verify'] };
  createPublicKey({ key: publicJwk, format: 'jwk' });
  return { credentialId, publicJwk, counter };
}

export function verifyAssertion({ credentialId, clientDataJSON, authenticatorData: authB64,
  signature, challenge, rpId, origin, registered }) {
  if (!registered || credentialId !== registered.credential_id ||
      registered.revoked_at) throw Error('device_not_registered');
  const clientRaw = clientData(clientDataJSON, 'webauthn.get', challenge, origin);
  const authenticatorRaw = decode64(authB64, 1500);
  const { counter } = authenticatorData(authenticatorRaw, rpId, false);
  if (authenticatorRaw.length !== 37) throw Error('invalid_assertion_data');
  const key = createPublicKey({ key: registered.public_key_jwk, format: 'jwk' });
  const signed = Buffer.concat([authenticatorRaw, sha(clientRaw)]);
  if (!verifySignature('sha256', signed, key, decode64(signature, 1500))) throw Error('invalid_device_signature');
  const last = Number(registered.sign_count);
  if (!Number.isSafeInteger(last) || last < 0 || (counter !== 0 && last !== 0 && counter <= last)) {
    throw Error('invalid_authenticator_counter');
  }
  return { counter };
}
