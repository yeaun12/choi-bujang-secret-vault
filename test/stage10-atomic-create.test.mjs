import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { createJudgeBNoteAtomic } from '../src/stage10-atomic-create.mjs';
import { noteScopeOwnerId } from '../src/resource-api-auth.mjs';

const runId = randomUUID(), userId = randomUUID();
const b = { kind: 'judge', identity: 'b', runId, userId };
const a = { ...b, identity: 'a' };
const id = randomUUID();
const note = { id, owner_id: noteScopeOwnerId(b), title: 'Synthetic',
  content: 'Synthetic safe note body' };

test('atomic B adapter binds only verified run and owner parameters', async () => {
  let called = 0;
  const db = { rpc(name, params) {
    called++;
    assert.equal(name, 'stage10_create_b_note');
    assert.equal(params.p_judge_run_id, runId);
    assert.equal(params.p_owner_id, note.owner_id);
    assert.equal(params.p_note_id, id);
    assert.equal(params.p_title, note.title);
    assert.equal(params.p_content, note.content);
    return { async single() {
      return { data: { note_id: id, owner_id: note.owner_id }, error: null };
    } };
  } };
  assert.deepEqual(await createJudgeBNoteAtomic({ identity: b, note, database: db }),
    { status: 201, id });
  assert.equal(called, 1);
});

test('atomic B adapter rejects A, student, foreign ownership before calling DB', async () => {
  let calls = 0;
  const database = { rpc() { calls++; throw new Error('should_not_call'); } };
  const identities = [a, { ...b, kind: 'student' }, b];
  const candidates = [note, note, { ...note, owner_id: noteScopeOwnerId(a) }];
  for (let i = 0; i < identities.length; i++) {
    const result = await createJudgeBNoteAtomic({
      identity: identities[i], note: candidates[i], database,
    });
    assert.equal(result.status, 503);
  }
  assert.equal(calls, 0);
});

test('missing function, DB rejection and network error are fail-closed', async () => {
  for (const database of [
    {},
    { rpc: () => ({ single: async () => ({ data: null,
      error: { code: '42883' } }) }) },
    { rpc: () => { throw new Error('network failure'); } },
    { rpc: () => ({ single: async () => ({ data: { note_id: id,
      owner_id: randomUUID() }, error: null }) }) },
  ]) {
    const result = await createJudgeBNoteAtomic({ identity: b, note, database });
    assert.equal(result.status, 503);
  }
});

test('duplicate note ID returns conflict without fallback insertion', async () => {
  const database = { rpc: () => ({
    single: async () => ({ data: null, error: { code: '23505' } }),
  }) };
  const result = await createJudgeBNoteAtomic({ identity: b, note, database });
  assert.deepEqual(result, { status: 409, code: 'duplicate_note_id' });
});
