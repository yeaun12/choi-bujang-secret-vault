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
