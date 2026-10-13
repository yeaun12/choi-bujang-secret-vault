import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runPostRestoreHttpRetests, permittedRetestOrigin } from
  '../src/stage10-postrestore-retest.mjs';
import { sha256 } from '../src/stage10-note-recovery.mjs';
import { noteScopeOwnerId } from '../src/resource-api-auth.mjs';

const B = { kind: 'judge', identity: 'b',
  runId: '123e4567-e89b-42d3-a456-426614174000',
  userId: '123e4567-e89b-42d3-a456-426614174001' };
const noteId = '123e4567-e89b-42d3-a456-426614174002';
const foreignId = '123e4567-e89b-42d3-a456-426614174003';
const auth = 'Bearer ' + ['testheader', 'testpayload', 'testsignature'].join('.');
const requestUrl = 'https://owner-app.vercel.app/api/restore';
const configuredAppUrl = 'https://owner-app.vercel.app/';
const expectedSha256 = sha256('restored text');
function setup({ foreign = foreignId, anonymousStatus = 401, content = 'restored text' } = {}) {
  const events = [], requests = [];
  const repository = {
    findFirstNoteIdByOwner: async (ownerId) => {
      assert.equal(ownerId, noteScopeOwnerId({ ...B, identity: 'a' }));
      return foreign;
    },
    appendAudit: async event => events.push(event),
  };
  const fetchImpl = async (url, opts) => {
    const u = new URL(url);
    requests.push({ pathname: u.pathname, search: u.search,
      authorized: Boolean(opts.headers.Authorization) });
    if (!opts.headers.Authorization) return Response.json(
      { error: 'Authentication required.' }, { status: anonymousStatus });
    if (u.pathname.endsWith(foreignId)) return Response.json(
      { error: 'Note not found.' }, { status: 404 });
    if (u.search) return Response.json({ error: 'Invalid note id.' }, { status: 400 });
    return Response.json({ id: noteId, title: 'fixture', body: content });
  };
  return { events, requests, repository, fetchImpl };
}
test('actual after-restore HTTP normal/denied requests are separately recorded', async () => {
  const demo = setup();
  const r = await runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl, configuredAppUrl, ...demo,
  });
  assert.equal(r.passed, true);
  assert.deepEqual(r.results.map(x => x.result), ['passed', 'passed', 'passed', 'passed']);
  assert.deepEqual(demo.requests.map(x => [x.pathname, x.authorized]), [
    ['/api/notes/' + noteId, true], ['/api/notes/' + noteId, false],
    ['/api/notes/' + noteId, true], ['/api/notes/' + foreignId, true],
  ]);
  assert.deepEqual(demo.events.map(x => x.event_kind),
    ['restore_verified', 'restore_verified', 'restore_verified', 'restore_verified']);
  assert.ok(demo.events.every(e => e.owner_id === noteScopeOwnerId(B)));
  assert.equal(JSON.stringify(demo.events).includes('restored text'), false);
  assert.equal(JSON.stringify(demo.events).includes('testsignature'), false);
});
test('anonymous access allowed causes a real failed retest, never a pass', async () => {
  const demo = setup({ anonymousStatus: 200 });
  const r = await runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl, configuredAppUrl, ...demo,
  });
  assert.equal(r.passed, false);
  assert.ok(r.results.some(x => x.check === 'anonymous_denied' && x.result === 'failed'));
  assert.ok(demo.events.some(x => x.event_kind === 'restore_failed'));
});
test('wrong content hash after restore fails a real normal GET check', async () => {
  const demo = setup({ content: 'still corrupted' });
  const r = await runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl, configuredAppUrl, ...demo,
  });
  assert.equal(r.passed, false);
  assert.equal(r.results[0].status, 200);
  assert.equal(r.results[0].result, 'failed');
});
test('missing judge A fixture is explicitly marked unexecuted, never passed', async () => {
  const demo = setup({ foreign: null });
  const r = await runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl, configuredAppUrl, ...demo,
  });
  assert.equal(r.results.at(-1).result, 'not_run_no_verified_a_note');
  assert.equal(r.passed, false);
  assert.equal(r.complete, false);
  assert.equal(demo.events.at(-1).event_kind, 'restore_rejected');
  assert.equal(demo.events.at(-1).reason_code, 'retest_foreign_not_run_no_a_note');
  assert.equal(demo.requests.length, 3);
});
test('untrusted user-controlled host or HTTP origin never receives the bearer', async () => {
  for (const bad of [
    'https://evil.vercel.app/api/restore',
    'http://owner-app.vercel.app/api/restore',
    'https://owner-app.vercel.app/api/restore?user=b',
  ]) {
    assert.throws(() => permittedRetestOrigin(bad, configuredAppUrl),
      /stage10_untrusted_retest_origin/u);
  }
  const demo = setup();
  await assert.rejects(runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl: 'https://evil.vercel.app/api/restore', configuredAppUrl, ...demo,
  }), /stage10_untrusted_retest_origin/u);
  assert.equal(demo.requests.length, 0);
});

test('audit writes fit existing stage 10 DB constraints; no migration required', async () => {
  const validKinds = new Set([
    'backup_created', 'backup_rejected',
    'restore_requested', 'restore_rejected', 'restore_applied',
    'restore_verified', 'restore_failed',
  ]);
  const demo = setup({ foreign: null });
  await runPostRestoreHttpRetests({
    identity: B, noteId, expectedSha256, authorization: auth,
    requestUrl, configuredAppUrl, ...demo,
  });
  assert.equal(demo.events.length, 4);
  assert.ok(demo.events.every(x => validKinds.has(x.event_kind)));
  assert.ok(demo.events.every(x => /^retest_[a-z0-9_]{1,57}$/u.test(x.reason_code)));
  assert.equal(demo.events.at(-1).event_kind, 'restore_rejected');
});
