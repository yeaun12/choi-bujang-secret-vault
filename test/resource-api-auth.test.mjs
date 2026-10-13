import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkStoredNoteOwner, getExactNoteId, isExactNoteCollection,
  isOwnedNoteList, isStoredNoteOwner, noteScopeOwnerId } from '../src/resource-api-auth.mjs';

const a = '123e4567-e89b-42d3-a456-426614174000';
const b = '123e4567-e89b-42d3-b456-426614174001';
const A = { kind: 'student', userId: a }, B = { kind: 'student', userId: b };
const fakeDB = (ownerId, error = null) => ({
  from: (table) => {
    assert.equal(table, 'notes');
    return { select: (field) => {
      assert.equal(field, 'owner_id');
      return { eq: (column, id) => {
        assert.equal(column, 'id'); assert.equal(id, a);
        return { maybeSingle: async () => ({
          data: ownerId ? { owner_id: ownerId } : null, error
        }) };
      } };
    } };
  },
});

test('검증된 사용자와 저장된 소유자만 일치할 때 허용', () => {
  assert.equal(isStoredNoteOwner(A, a), true);
  assert.equal(isStoredNoteOwner(B, a), false);
  assert.equal(isStoredNoteOwner({ kind: 'guest', userId: a, role: 'instructor' }, a), false);
  assert.equal(isStoredNoteOwner({ kind: 'student', role: 'instructor' }, a), false);
});

test('메모 목록에 다른 사용자 자료가 섞이면 거부', () => {
  assert.equal(isOwnedNoteList(A, [{ owner_id: a }]), true);
  assert.equal(isOwnedNoteList(A, [{ owner_id: a }, { owner_id: b }]), false);
  assert.equal(isOwnedNoteList(A, null), false);
});

test('수정 전 DB 소유권 재확인과 실패 시 차단', async () => {
  assert.equal(await checkStoredNoteOwner(fakeDB(a), A, a), 'allowed');
  assert.equal(await checkStoredNoteOwner(fakeDB(a), B, a), 'denied');
  assert.equal(await checkStoredNoteOwner(fakeDB(null), A, a), 'denied');
  assert.equal(await checkStoredNoteOwner(fakeDB(null, { code: 'db_error' }), A, a), 'error');
});

test('정확한 자료 경로만 자료 ID로 인정', () => {
  const path = (s) => ({ url: `https://example.test${s}` });
  assert.equal(getExactNoteId(path(`/api/notes/${a}`)), a);
  assert.equal(isExactNoteCollection(path('/api/notes')), true);
  assert.equal(getExactNoteId(path('/api/notes/export')), null);
  assert.equal(getExactNoteId(path(`/api/notices/${a}`)), null);
  assert.equal(getExactNoteId(path(`/api/notes/${a}/export`)), null);
  assert.equal(isExactNoteCollection(path('/api/notes/export')), false);
});

test('심판이 같은 sub를 보내도 서명 검증된 A/B 구역은 독립이다', async () => {
  const subject = '123e4567-e89b-42d3-a456-426614174000';
  const runId = '123e4567-e89b-42d3-b456-426614174001';
  const judgeA = { kind: 'judge', userId: subject, runId, identity: 'a' };
  const judgeB = { kind: 'judge', userId: subject, runId, identity: 'b' };
  const ownerA = noteScopeOwnerId(judgeA);
  const ownerB = noteScopeOwnerId(judgeB);
  assert.ok(/^[0-9a-f-]{36}$/u.test(ownerA));
  assert.notEqual(ownerA, subject);
  assert.notEqual(ownerA, ownerB);
  assert.equal(ownerA, noteScopeOwnerId({ ...judgeA }));
  assert.equal(isStoredNoteOwner(judgeA, ownerA), true);
  assert.equal(isStoredNoteOwner(judgeB, ownerA), false);
  assert.equal(isStoredNoteOwner(judgeB, ownerB), true);
  assert.equal(isOwnedNoteList(judgeB, [{ owner_id: ownerA }]), false);
  assert.equal(isOwnedNoteList(judgeB, [{ owner_id: ownerB }]), true);
  assert.equal(noteScopeOwnerId({ kind: 'judge', userId: subject, identity: 'a' }), null);
  assert.equal(noteScopeOwnerId({ kind: 'student', userId: subject, role: 'instructor' }), subject);
});

test('실제 동적 ID의 저장된 소유자는 동일 sub라도 심판 A만 읽고 B는 차단', async () => {
  const sharedSub = '123e4567-e89b-42d3-a456-426614174000';
  const runId = '123e4567-e89b-42d3-b456-426614174001';
  const judgeA = { kind: 'judge', userId: sharedSub, runId, identity: 'a' };
  const judgeB = { kind: 'judge', userId: sharedSub, runId, identity: 'b' };
  const ownerA = noteScopeOwnerId(judgeA);
  assert.equal(isStoredNoteOwner(judgeA, ownerA), true);
  assert.equal(isStoredNoteOwner(judgeB, ownerA), false);
  assert.equal(await checkStoredNoteOwner(fakeDB(ownerA), judgeA, sharedSub), 'allowed');
  assert.equal(await checkStoredNoteOwner(fakeDB(ownerA), judgeB, sharedSub), 'denied');
});
