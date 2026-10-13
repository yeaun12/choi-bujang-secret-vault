import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hasInstructorMembership, noticePath, validPrincipal } from '../src/instructor-authorization.mjs';
const a = '123e4567-e89b-42d3-a456-426614174000';
const principal = { kind: 'student', userId: a };
const stub = (record, error = null) => ({ from: (table) => {
  assert.equal(table, 'instructor_memberships');
  return { select: () => ({ eq: (field, value) => {
    assert.equal(field, 'user_id'); assert.equal(value, a);
    return { maybeSingle: async () => ({ data: record, error }) };
  } }) };
} });

test('서버 검증 사용자만 강사 권한 확인 대상', () => {
  assert.equal(validPrincipal(principal), true);
  assert.equal(validPrincipal({ kind: 'student', role: 'instructor' }), false);
  assert.equal(validPrincipal({ kind: 'guest', userId: a }), false);
});
test('DB에 등록된 강사만 쓰기 가능', async () => {
  assert.equal(await hasInstructorMembership(stub({ user_id: a }), principal), true);
  assert.equal(await hasInstructorMembership(stub(null), principal), false);
  assert.equal(await hasInstructorMembership(stub({ user_id: a }, { code: 'error' }), principal), false);
  assert.equal(await hasInstructorMembership(stub({ user_id: a }), { kind: 'judge', userId: a }), false);
});
test('공지 컬렉션과 정확한 항목 ID만 분류', () => {
  const p = (suffix) => ({ url: 'https://test.example' + suffix });
  assert.deepEqual(noticePath(p('/api/instructor-notices')), { collection: true });
  assert.deepEqual(noticePath(p('/api/instructor-notices/' + a)), { collection: false, id: a });
  assert.equal(noticePath(p('/api/instructor-notices/export')), null);
  assert.equal(noticePath(p('/api/instructor-notices/' + a + '/export')), null);
});
