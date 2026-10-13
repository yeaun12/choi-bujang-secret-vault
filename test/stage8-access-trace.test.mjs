import { test } from 'node:test';
import assert from 'node:assert/strict';
import { traceStage8Access } from '../src/stage8-access-trace.mjs';

test('only verified judge A/B events with fixed safe labels are logged', () => {
  const rows = [];
  const emit = (...args) => rows.push(args);
  const a = { kind: 'judge', userId: 'sensitive-user-id', runId: 'sensitive-run-id', identity: 'a' };
  assert.equal(traceStage8Access(a, 'note_item_get', 'owner_match', 200, emit), true);
  assert.equal(traceStage8Access({ ...a, identity: 'b' }, 'note_item_get', 'not_found_or_not_owner', 404, emit), true);
  assert.equal(traceStage8Access({ ...a, kind: 'student' }, 'note_item_get', 'owner_match', 200, emit), false);
  assert.equal(traceStage8Access(a, 'note_item_get', 'sensitive-user-id', 200, emit), false);
  assert.equal(traceStage8Access(a, '/api/notes/sensitive-user-id', 'owner_match', 200, emit), false);
  assert.equal(rows.length, 2);
  assert.equal(rows[0][0], 'S08_JUDGE_ACCESS');
  assert.deepEqual(JSON.parse(rows[0][1]), {
    kind: 'judge', actor: 'a', operation: 'note_item_get', outcome: 'owner_match', status: 200,
  });
  assert.equal(JSON.stringify(rows).includes('sensitive-user-id'), false);
  assert.equal(JSON.stringify(rows).includes('sensitive-run-id'), false);
});
