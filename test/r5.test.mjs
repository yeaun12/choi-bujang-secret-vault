import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const baseConfig = {
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
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

test('deployment identity rejects unsupported stages', () => {
  const config = { ...baseConfig, step: 4 };

  assert.throws(() => deploymentIdentity(env, config));
});
