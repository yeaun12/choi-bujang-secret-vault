import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { classifyResourceRoute, decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const id = '123e4567-e89b-42d3-a456-426614174000';
const base = () => ({
  ...fixtureRequests().normal,
  requestId: randomUUID(),
  method: 'GET',
  path: `/api/notes/${id}`,
  route: 'GET /api/notes/:id',
});

test('기기 등록·기존 위험 탐지 규칙과 8단계 규칙을 유지한다', async () => {
  for (const rule of ['device_registered', 'step_up_required', 'resource_scope'])
    assert.ok(RULE_IDS.includes(rule));
  assert.equal((await decide({ ...base(), deviceRegistered: false })).reasonCode, 'device_not_registered');
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(suspicious)).decision, 'step_up');
});

test('메모 목록 및 개별 자원 접근을 정확한 메서드·경로로 분류한다', async () => {
  for (const [method, path, route, resourceId] of [
    ['GET', '/api/notes', 'GET /api/notes', 'note:collection'],
    ['POST', '/api/notes', 'POST /api/notes', 'note:collection'],
    ['GET', `/api/notes/${id}`, 'GET /api/notes/:id', `note:${id}`],
    ['PUT', `/api/notes/${id}`, 'PUT /api/notes/:id', `note:${id}`],
    ['DELETE', `/api/notes/${id}`, 'DELETE /api/notes/:id', `note:${id}`],
  ]) {
    const req = { ...base(), method, path, route };
    assert.equal(classifyResourceRoute(req)?.resourceId, resourceId);
    assert.equal((await decide(req)).decision, 'allow');
  }
});

test('허용되지 않은 구역·강사 공지 수정·기능 경로는 거부한다', async () => {
  const invalid = [
    { method: 'PUT', path: `/api/notices/${id}`, route: 'PUT /api/notices/:id' },
    { method: 'PUT', path: `/api/instructor-notices/${id}`, route: 'PUT /api/instructor-notices/:id' },
    { method: 'GET', path: `/api/notes/${id}`, route: 'GET /api/notices/:id' },
    { method: 'GET', path: '/api/notes/export', route: 'GET /api/notes/:id' },
    { method: 'POST', path: `/api/notes/${id}`, route: 'POST /api/notes/:id' },
    { method: 'GET', path: `/api/notes/${id}?role=instructor`, route: 'GET /api/notes/:id' },
    { method: 'GET', path: `/api/notes/${id}`, route: 'POST /api/notes/:id' },
    { method: 'GET', path: '/api/unknown', route: 'GET /api/unknown' },
    { method: 'GET', path: `/api/notes/${id}`, route: 'GET /api/notes/:id', queryLength: 12 },
  ];
  for (const details of invalid) {
    const req = { ...base(), ...details, role: 'instructor', headers: { 'x-role': 'instructor' } };
    assert.equal(classifyResourceRoute(req), null, JSON.stringify(details));
    const decision = await decide(req);
    assert.equal(decision.decision, 'deny', JSON.stringify(details));
    assert.equal(decision.reasonCode, 'resource_access_denied');
  }
});

test('가상 7단계 경로만 특례로 유지하고 운영의 기능 경로로 확장하지 않는다', async () => {
  const { normal } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  const modified = { ...normal, path: '/notes/export' };
  assert.equal((await decide(modified)).decision, 'deny');
  const fake = { ...normal, classId: 'real_class' };
  assert.equal((await decide(fake)).decision, 'deny');
});

test('같은 경로라도 7단계 복합 이상 사건은 여전히 추가 인증을 요구한다', async () => {
  const normal = base();
  const risk = {
    ...normal,
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    stepUp: { verified: false, authAgeSeconds: null },
  };
  assert.equal((await decide(risk)).decision, 'step_up');
  assert.equal((await decide({ ...risk, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
});

test('본인 메모 소유권은 자원 경로만으로 확인할 수 없다', () => {
  const subjectA = { ...base(), subjectId: 'anonymous_subject_A' };
  const subjectB = { ...base(), subjectId: 'anonymous_subject_B' };
  assert.deepEqual(classifyResourceRoute(subjectA), classifyResourceRoute(subjectB));
  // 소유권 차단의 최종 강제 지점은 자료 API의 저장된 owner_id 필터다.
});
