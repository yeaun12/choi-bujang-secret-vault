import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RESOURCE_ZONES, resourceIdFor, noteResourceFromApiPath,
  instructorNoticeResourceId } from '../src/resource-id.mjs';

const id = '123e4567-e89b-42d3-a456-426614174000';

test('메모와 강사 공지는 같은 UUID여도 서로 다른 자원 ID다', () => {
  assert.equal(resourceIdFor(RESOURCE_ZONES.NOTE, id), `note:${id}`);
  assert.equal(instructorNoticeResourceId(id), `instructor_notice:${id}`);
  assert.notEqual(resourceIdFor(RESOURCE_ZONES.NOTE, id), instructorNoticeResourceId(id));
});

test('기존 메모 API 주소에서 목록과 개별 자원을 정확히 구별한다', () => {
  assert.deepEqual(noteResourceFromApiPath('/api/notes'), { zone: 'note', resourceId: 'note:collection' });
  assert.deepEqual(noteResourceFromApiPath(`/api/notes/${id}`), { zone: 'note', resourceId: `note:${id}` });
});

test('쿼리, 기능 경로, 잘못된 ID는 자원 ID로 받아들이지 않는다', () => {
  for (const path of ['/api/notes?role=instructor', '/api/notes/export', '/api/notes/../export',
    `/api/notes/${id}?role=instructor`, '/api/notes/invalid', '/api/notes/123/extra',
    '/api/notices', '/api/announcements', '/api/notes/', null, undefined]) {
    assert.equal(noteResourceFromApiPath(path), null, String(path));
  }
  assert.equal(instructorNoticeResourceId('export'), null);
  assert.equal(resourceIdFor('admin', id), null);
});
