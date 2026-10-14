import test from 'node:test';
import assert from 'node:assert/strict';
import { runAttackChecks } from '../src/attack-check.mjs';

test('step 12 submission bundle uses only public HTTPS GETs and marks restricted checks not_run', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(url);
    const method = options.method ?? 'GET';
    requests.push({ method, url: parsed.href, headers: options.headers });
    assert.equal(parsed.protocol, 'https:');
    assert.equal(method, 'GET', 'stage 12 bundle may never issue write requests');
    assert.equal(options.body, undefined);
    const status = parsed.pathname === '/data.json' ? 404 : 401;
    return new Response(JSON.stringify({ error: 'Student login required.' }), {
      status, headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    const attempts = await runAttackChecks({
      step: 12, publicAppUrl: 'https://stage12-safe-test.invalid/',
      sampleMarker: 'SAMPLE_NOTE_1',
    });
    assert.deepEqual(requests.map(({url}) => new URL(url).pathname), [
      '/data.json',
      '/api/notes',
      '/api/notes',
      '/api/instructor-notices',
      '/api/war-room',
    ]);
    assert.equal(attempts.length, 13);
    assert.equal(attempts.filter(a => a.observed === 'not_run').length, 8);
    assert.equal(attempts.filter(a => a.observed !== 'not_run').length, 5);
    assert(attempts.some(a => a.attackId === 'anonymous_war_room_read_denied'
      && a.observed.includes('HTTP 401')));
    assert(attempts.every(a => Object.keys(a).sort().join(',') === 'attackId,expected,observed'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
