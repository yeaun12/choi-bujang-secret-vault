import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';

const fixed = 'choi-bujang-secret-vault-blush.vercel.app';
const deployment = 'choi-bujang-secret-vault-df77fvq2e-yeaun.vercel.app';
const issuer = 'https://aleph-judge-production.up.railway.app/defense/judge';
const config = {
  repoUrl: 'https://github.com/yeaun12/choi-bujang-secret-vault',
  publicAppUrl: 'https://' + fixed + '/',
  judgeIssuer: issuer,
  identityProvider: {
    issuer: 'https://example-project.supabase.co/auth/v1',
    jwksUrl: 'https://example-project.supabase.co/auth/v1/.well-known/jwks.json',
    audience: 'authenticated',
  },
};
const userId = '123e4567-e89b-42d3-a456-426614174001';
const runId = '123e4567-e89b-42d3-a456-426614174002';

test('verified judge-B token accepts fixed and actual Vercel deployment audiences', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const verifier = createLoginVerifier({
    config, deploymentHost: deployment,
    judgeKeySet: async () => publicKey,
    supabaseClient: { auth: { getClaims: async () => ({ data: null, error: null }) } },
  });
  async function token(aud) {
    return new SignJWT({ aleph_role: 'judge', aleph_identity: 'b', aleph_run: runId })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(issuer).setAudience(aud).setSubject(userId)
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  }
  for (const accepted of [fixed, deployment]) {
    const identity = await verifier('Bearer ' + await token(accepted));
    assert.deepEqual(identity && { kind: identity.kind, identity: identity.identity },
      { kind: 'judge', identity: 'b' });
  }
  assert.equal(await verifier('Bearer ' + await token('attacker.vercel.app')), null);
  assert.equal(await verifier('Bearer ' + await token('other-project-123.vercel.app')), null);
});

test('untrusted deployment names never expand the accepted judge audience', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const forgeAud = 'other-project-123.vercel.app';
  for (const host of [forgeAud, 'https://' + deployment, 'choi-bujang-secret-vault-malicious.example.com']) {
    const verifier = createLoginVerifier({
      config, deploymentHost: host,
      judgeKeySet: async () => publicKey,
      supabaseClient: { auth: { getClaims: async () => ({ data: null, error: null }) } },
    });
    const jwt = await new SignJWT({ aleph_role: 'judge', aleph_identity: 'b', aleph_run: runId })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(issuer).setAudience(host).setSubject(userId)
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    assert.equal(await verifier('Bearer ' + jwt), null);
  }
});

test('officially signed non-v4 UUIDs and JWT audience arrays retain bounded identity', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const verifier = createLoginVerifier({
    config, deploymentHost: deployment,
    judgeKeySet: async () => publicKey,
    supabaseClient: { auth: { getClaims: async () => ({ data: null, error: null }) } },
  });
  // UUID version is not an authorization role. The issuer's valid signature,
  // strict trusted audiences and signed B identity are the security boundary.
  const v1UserId = '123e4567-e89b-12d3-a456-426614174001';
  const v5RunId = '123e4567-e89b-52d3-a456-426614174002';
  const now = Math.floor(Date.now() / 1000);
  const signed = (aud, options = {}) => new SignJWT({
    aleph_role: options.role ?? 'judge', aleph_identity: options.actor ?? 'b',
    aleph_run: v5RunId,
  }).setProtectedHeader({ alg: 'ES256' })
    .setIssuer(options.issuer ?? issuer).setAudience(aud).setSubject(v1UserId)
    .setIssuedAt(options.issuedAt ?? now - 3600)
    .setExpirationTime(options.expiresAt ?? now + 600).sign(privateKey);
  const verified = await verifier('Bearer ' + await signed([fixed, deployment]));
  assert.deepEqual(verified, {
    kind: 'judge', userId: v1UserId, runId: v5RunId, identity: 'b',
  });
  const { noteScopeOwnerId } = await import('../src/resource-api-auth.mjs');
  assert.match(noteScopeOwnerId(verified), /^[0-9a-f-]{36}$/u);
  for (const invalid of [
    signed(['malicious.vercel.app']),
    signed([fixed], { issuer: 'https://different-issuer.example.org/defense/judge' }),
    signed([fixed], { role: 'student' }),
    signed([fixed], { expiresAt: now - 20 }),
    signed([fixed], { issuedAt: now + 60 }),
  ]) assert.equal(await verifier('Bearer ' + await invalid), null);
});
