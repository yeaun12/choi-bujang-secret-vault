import { isIP } from 'node:net';
import { createClient } from '@supabase/supabase-js';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
// A judge-signed subject/run is a canonical RFC 4122 UUID; the stage contract
// does not require that every legitimate issuer chooses version 4 specifically.
const JUDGE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;
const DEPLOYMENT_HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/u;

// Only Vercel's system-provided deployment hostname may extend the trusted
// judge audience. Never derive this from request Host, Origin or forwarded headers.
function verifiedDeploymentAudience(config, deploymentHost) {
  if (typeof deploymentHost !== 'string' || !DEPLOYMENT_HOST.test(deploymentHost)) return null;
  try {
    const repo = new URL(config.repoUrl);
    if (repo.origin !== 'https://github.com' || repo.search || repo.hash) return null;
    const names = repo.pathname.split('/').filter(Boolean);
    if (names.length !== 2 || !/^[a-z0-9][a-z0-9-]*$/u.test(names[1])) return null;
    // Vercel-generated deployment URLs are prefixed with the exact project/repo slug.
    if (!deploymentHost.startsWith(names[1] + '-')) return null;
    return deploymentHost;
  } catch { return null; }
}

function httpsUrl(value, path) {
  if (typeof value !== 'string' || value !== value.trim()) throw new TypeError('invalid_login_issuer');
  let url;
  try { url = new URL(value); } catch { throw new TypeError('invalid_login_issuer'); }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.port
      || url.pathname !== path || url.search || url.hash || !host.includes('.')
      || host === 'localhost' || isIP(host)
      || host.endsWith('.local') || host.endsWith('.internal')
      || host.endsWith('.invalid') || host.endsWith('.test') || host.endsWith('.example')) {
    throw new TypeError('invalid_login_issuer');
  }
  return url;
}

function verifiedConfig(config, deploymentHost) {
  const judge = httpsUrl(config?.judgeIssuer, '/defense/judge');
  const app = httpsUrl(config?.publicAppUrl, '/');
  if (!app.hostname.endsWith('.vercel.app')) throw new TypeError('invalid_login_app_origin');
  const student = httpsUrl(config?.identityProvider?.issuer, '/auth/v1');
  if (student.origin === judge.origin || student.origin === app.origin
      || config.identityProvider.jwksUrl !== `${student.href}/.well-known/jwks.json`
      || typeof config.identityProvider.audience !== 'string'
      || !/^[a-zA-Z0-9._:-]{1,120}$/u.test(config.identityProvider.audience)) {
    throw new TypeError('invalid_student_identity_provider');
  }
  const deploymentAudience = verifiedDeploymentAudience(config, deploymentHost);
  const judgeAudiences = [...new Set([app.hostname, deploymentAudience].filter(Boolean))];
  return { judgeIssuer: judge.href, judgeJwksUrl: `${judge.href}/.well-known/jwks.json`,
    judgeAudiences, studentIssuer: student.href,
    studentAudience: config.identityProvider.audience, studentUrl: student.origin };
}

// Create once in the server runtime. The judge intake separately compares the
// checked-in judgeIssuer to its registered operator issuer before any attack.
export function createLoginVerifier({ config, supabaseSecretKey, judgeKeySet,
  supabaseClient, deploymentHost = process.env.VERCEL_URL } = {}) {
  const bound = verifiedConfig(config, deploymentHost);
  if (!supabaseClient && (typeof supabaseSecretKey !== 'string'
      || !supabaseSecretKey.trim() || supabaseSecretKey !== supabaseSecretKey.trim())) {
    throw new TypeError('missing_supabase_secret_key');
  }
  const keys = judgeKeySet ?? createRemoteJWKSet(new URL(bound.judgeJwksUrl),
    { timeoutDuration: 5000, cacheMaxAge: 5 * 60 * 1000 });
  const supabase = supabaseClient ?? createClient(bound.studentUrl, supabaseSecretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  if (typeof keys !== 'function' || typeof supabase?.auth?.getClaims !== 'function') {
    throw new TypeError('invalid_login_verifier_configuration');
  }

  return async function verifyLoginAuthorization(authorization) {
    if (typeof authorization !== 'string' || authorization.length > 8192) return null;
    const match = BEARER.exec(authorization);
    if (!match) return null;
    const token = match[1];
    let issuer;
    try { issuer = decodeJwt(token).iss; } catch { return null; }
    if (issuer === bound.judgeIssuer) {
      try {
        const { payload, protectedHeader } = await jwtVerify(token, keys, {
          issuer: bound.judgeIssuer, audience: bound.judgeAudiences, algorithms: ['ES256'],
          clockTolerance: 5,
        });
        // jose already verifies the issuer, signature, expiry, nbf and an
        // intersection with our explicit, trusted audience allowlist. JWT
        // permits either string or string[] audience values; do not reject
        // a valid array after the library has verified its membership.
        // A signed token must still be issued, expiring, correctly typed and
        // not future-dated. Its age/UUID version is not a separate role proof.
        if (protectedHeader.alg !== 'ES256'
            || !JUDGE_UUID.test(payload.sub ?? '') || !JUDGE_UUID.test(payload.aleph_run ?? '')
            || payload.aleph_role !== 'judge'
            || !['a', 'b'].includes(payload.aleph_identity)
            || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)
            || payload.iat > Math.floor(Date.now() / 1000) + 5
            || payload.exp <= payload.iat) return null;
        return Object.freeze({ kind: 'judge', userId: payload.sub,
          runId: payload.aleph_run, identity: payload.aleph_identity });
      } catch { return null; }
    }
    if (issuer === bound.studentIssuer) {
      try {
        // Supabase verifies asymmetric keys locally through JWKS and shared-secret
        // tokens through its Auth server. Never decode and trust a student claim here.
        const { data, error } = await supabase.auth.getClaims(token);
        const claims = data?.claims;
        if (error || !claims || claims.iss !== bound.studentIssuer
            || claims.aud !== bound.studentAudience
            || claims.role !== 'authenticated' || !UUID.test(claims.sub ?? '')
            || !Number.isSafeInteger(claims.exp)
            || claims.exp <= Math.floor(Date.now() / 1000)) return null;
        return Object.freeze({ kind: 'student', userId: claims.sub });
      } catch { return null; }
    }
    return null;
  };
}
