import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const baseConfig = {
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
  allowedRoutes: [
    'POST /api/auth',
    'PUT /api/auth',
    'DELETE /api/auth',
    'GET /api/notes',
    'POST /api/notes',
    'GET /api/notes/:id',
    'PUT /api/notes/:id',
    'DELETE /api/notes/:id',
  ],
};

const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity preserves stage 1 behavior', () => {
  const config = { ...baseConfig, step: 1 };

  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    allowedRoutes: config.allowedRoutes,
    originalApiUrl: config.originalApiUrl,
  });

  assert.throws(() =>
    deploymentIdentity(
      { ...env, VERCEL_GIT_PROVIDER: undefined },
      config
    )
  );

  assert.throws(() =>
    deploymentIdentity(
      { ...env, VERCEL_GIT_COMMIT_SHA: 'short' },
      config
    )
  );
});

test('build identity supports stage 2 without changing the schema', () => {
  const config = { ...baseConfig, step: 2 };

  const identity = deploymentIdentity(env, config);

  assert.equal(identity.schema, 'aleph.defense.deployment.v1');
  assert.equal(identity.step, 2);
  assert.equal(identity.sampleMarker, 'SAMPLE_NOTE_1');
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
});

test('stage 1 attack check reads public data.json anonymously', async () => {
  const originalFetch = globalThis.fetch;
  const config = { ...baseConfig, step: 1 };

  let requestUrl;
  let options;

  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;

      return new Response(
        JSON.stringify({
          sampleMarker: 'SAMPLE_NOTE_1',
          notes: [{ title: 'sample', content: 'sample content' }],
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }
      );
    };

    const [result] = await runAttackChecks(config);

    assert.equal(
      requestUrl,
      'https://student-defense.vercel.app/data.json'
    );
    assert.equal(options.redirect, 'error');
    assert.equal(result.attackId, 'anonymous_note_read');
    assert.match(result.observed, /Public notes are visible/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 2 removes static data and keeps the server API public', async () => {
  const originalFetch = globalThis.fetch;
  const config = { ...baseConfig, step: 2 };

  const requestedUrls = [];

  try {
    globalThis.fetch = async (url) => {
      const requestUrl = String(url);
      requestedUrls.push(requestUrl);

      if (requestUrl.endsWith('/data.json')) {
        return new Response('Not Found', { status: 404 });
      }

      if (requestUrl.endsWith('/api/notes')) {
        return new Response(
          JSON.stringify({
            sampleMarker: 'SAMPLE_NOTE_1',
            notes: [
              { title: 'sample-1', content: 'content-1' },
              { title: 'sample-2', content: 'content-2' },
              { title: 'sample-3', content: 'content-3' },
              { title: 'sample-4', content: 'content-4' },
            ],
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }
        );
      }

      return new Response('Unexpected request', { status: 500 });
    };

    const results = await runAttackChecks(config);

    assert.deepEqual(requestedUrls, [
      'https://student-defense.vercel.app/data.json',
      'https://student-defense.vercel.app/api/notes',
    ]);

    assert.equal(results.length, 2);

    assert.equal(
      results[0].attackId,
      'static_note_file_removed'
    );
    assert.match(results[0].observed, /HTTP 404/u);

    assert.equal(
      results[1].attackId,
      'anonymous_api_note_read'
    );
    assert.match(results[1].observed, /4 sample notes/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity supports stage 5', () => {
  const config = {
    ...baseConfig,
    step: 5,
    originalApiUrl:
      'https://student-project.supabase.co/rest/v1/notes',
  };

  const identity = deploymentIdentity(env, config);

  assert.equal(identity.schema, 'aleph.defense.deployment.v1');
  assert.equal(identity.step, 5);
  assert.equal(identity.sampleMarker, 'SAMPLE_NOTE_1');
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.equal(
    identity.originalApiUrl,
    config.originalApiUrl
  );
});

test('deployment identity supports stage 6 without changing metadata', () => {
  const config = {
    ...baseConfig,
    step: 6,
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/notes',
  };
  const identity = deploymentIdentity(env, config);
  assert.equal(identity.step, 6);
  assert.equal(identity.schema, 'aleph.defense.deployment.v1');
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
});

test('stage 6 self-check retains HTTP evidence, not invented device checks', async () => {
  const originalFetch = globalThis.fetch;
  const config = { ...baseConfig, step: 6 };
  const requests = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const pathname = new URL(url).pathname;
      requests.push([pathname, init.method ?? 'GET']);
      if (pathname === '/data.json') {
        return new Response('Not Found', { status: 404 });
      }
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks(config);
    assert.deepEqual(requests, [
      ['/data.json', 'GET'],
      ['/api/notes', 'GET'],
      ['/api/notes', 'POST'],
      ['/api/notes', 'GET'],
    ]);
    assert.deepEqual(results.map((item) => item.attackId), [
      'static_note_file_removed',
      'anonymous_note_list_denied',
      'anonymous_note_create_denied',
      'invalid_login_token_denied',
    ]);
    assert.ok(results.every((item) => /HTTP (401|404)/u.test(item.observed)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity supports stage 7 without changing metadata', () => {
  const config = {
    ...baseConfig,
    step: 7,
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/notes',
  };
  const identity = deploymentIdentity(env, config);
  assert.equal(identity.step, 7);
  assert.equal(identity.schema, 'aleph.defense.deployment.v1');
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
});

test('stage 7 self-check retains actual HTTP evidence, not simulated re-login evidence', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const pathname = new URL(url).pathname;
      requests.push([pathname, init.method ?? 'GET']);
      if (pathname === '/data.json') return new Response('Not Found', { status: 404 });
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks({ ...baseConfig, step: 7 });
    assert.deepEqual(requests, [
      ['/data.json', 'GET'], ['/api/notes', 'GET'],
      ['/api/notes', 'POST'], ['/api/notes', 'GET'],
    ]);
    assert.equal(results.length, 4);
    assert.ok(results.every((item) => /HTTP (401|404)/u.test(item.observed)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity rejects unsupported stages', () => {
  const config = { ...baseConfig, step: 13 };
  assert.throws(() => deploymentIdentity(env, config));
});

test('deployment identity supports stage 8 with notice API route metadata', () => {
  const config = {
    ...baseConfig,
    step: 8,
    allowedRoutes: [...baseConfig.allowedRoutes, 'GET /api/instructor-notices', 'POST /api/instructor-notices', 'GET /api/instructor-notices/:id', 'PUT /api/instructor-notices/:id'],
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/notes',
  };
  const result = deploymentIdentity(env, config);
  assert.equal(result.step, 8);
  assert.deepEqual(result.allowedRoutes, config.allowedRoutes);
  assert.equal(result.judgeIssuer, config.judgeIssuer);
  assert.equal(result.originalApiUrl, config.originalApiUrl);
});

test('stage 8 self-check records anonymous notice denials without account tokens', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const pathname = new URL(url).pathname;
      requests.push([pathname, init.method ?? 'GET', init.headers?.Authorization ?? null]);
      if (pathname === '/data.json') return new Response('Not Found', { status: 404 });
      return new Response(JSON.stringify({ error: 'Authentication required.' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks({ ...baseConfig, step: 8 });
    assert.equal(results.length, 6);
    assert.deepEqual(requests.map(([path, method]) => [path, method]), [
      ['/data.json', 'GET'],
      ['/api/notes', 'GET'],
      ['/api/notes', 'POST'],
      ['/api/notes', 'GET'],
      ['/api/instructor-notices', 'GET'],
      ['/api/instructor-notices', 'POST'],
    ]);
    assert.ok(requests.every(([, , auth]) => auth === null ||
      auth === 'Bearer bad.token.value'));
    assert.ok(results.every(item => /HTTP (401|404)/u.test(item.observed)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity supports stage 9 with existing route metadata', () => {
  const config = {
    ...baseConfig, step: 9,
    allowedRoutes: [...baseConfig.allowedRoutes,
      'GET /api/instructor-notices', 'POST /api/instructor-notices',
      'GET /api/instructor-notices/:id', 'PUT /api/instructor-notices/:id'],
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/notes',
  };
  const result = deploymentIdentity(env, config);
  assert.equal(result.step, 9);
  assert.equal(result.schema, 'aleph.defense.deployment.v1');
  assert.deepEqual(result.allowedRoutes, config.allowedRoutes);
  assert.equal(result.judgeIssuer, config.judgeIssuer);
  assert.equal(result.originalApiUrl, config.originalApiUrl);
});

test('stage 9 self-check preserves observed anonymous HTTP checks', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(url).pathname;
      const method = init.method ?? 'GET';
      requests.push([path, method, init.headers?.Authorization ?? null]);
      if (path === '/data.json') return new Response('Not Found', { status: 404 });
      return new Response(JSON.stringify({ error: 'Authentication required.' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const attempts = await runAttackChecks({ ...baseConfig, step: 9 });
    assert.equal(attempts.length, 6);
    assert.deepEqual(requests.map(([path, method]) => [path, method]), [
      ['/data.json', 'GET'],
      ['/api/notes', 'GET'],
      ['/api/notes', 'POST'],
      ['/api/notes', 'GET'],
      ['/api/instructor-notices', 'GET'],
      ['/api/instructor-notices', 'POST'],
    ]);
    assert.ok(requests.every(([, , auth]) =>
      auth === null || auth === 'Bearer bad.token.value'));
    assert.ok(attempts.every(item => /HTTP (401|404)/u.test(item.observed)));
    assert.equal(attempts.some(item => item.attackId.includes('revocation')), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('deployment identity supports stage 10 with one-note restore route', () => {
  const config = {
    ...baseConfig, step: 10,
    allowedRoutes: [...baseConfig.allowedRoutes,
      'GET /api/instructor-notices', 'POST /api/instructor-notices',
      'GET /api/instructor-notices/:id', 'PUT /api/instructor-notices/:id',
      'POST /api/restore'],
    originalApiUrl: 'https://student-project.supabase.co/rest/v1/notes',
    restoreRoute: '/api/restore',
  };
  const identity = deploymentIdentity(env, config);
  assert.equal(identity.step, 10);
  assert.equal(identity.restoreRoute, '/api/restore');
  assert.throws(() => deploymentIdentity(env, { ...config, restoreRoute: undefined }));
  assert.throws(() => deploymentIdentity(env, { ...config,
    allowedRoutes: config.allowedRoutes.filter(route => route !== 'POST /api/restore') }));
  assert.equal(identity.schema, 'aleph.defense.deployment.v1');
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  assert.equal(identity.judgeIssuer, config.judgeIssuer);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
});

test('stage 10 self-check uses real anonymous HTTP evidence for recovery denial', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(url).pathname;
      const method = init.method ?? 'GET';
      requests.push([path, method, init.headers?.Authorization ?? null]);
      if (path === '/data.json') return new Response('Not Found', { status: 404 });
      return new Response(JSON.stringify({ error: 'Authentication required.' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const attempts = await runAttackChecks({ ...baseConfig, step: 10 });
    assert.equal(attempts.length, 7);
    assert.deepEqual(requests.map(([path, method]) => [path, method]), [
      ['/data.json', 'GET'],
      ['/api/notes', 'GET'],
      ['/api/notes', 'POST'],
      ['/api/notes', 'GET'],
      ['/api/instructor-notices', 'GET'],
      ['/api/instructor-notices', 'POST'],
      ['/api/restore', 'POST'],
    ]);
    assert.ok(requests.every(([, , auth]) =>
      auth === null || auth === 'Bearer bad.token.value'));
    assert.ok(attempts.every(item => /HTTP (401|404)/u.test(item.observed)));
    assert.equal(attempts.at(-1).attackId, 'anonymous_note_restore_denied');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
