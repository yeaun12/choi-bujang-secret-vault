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

test('메모 목록은 정확한 메서드·경로로 분류한다', async () => {
  for (const [method, path, route] of [
    ['GET', '/api/notes', 'GET /api/notes'],
    ['POST', '/api/notes', 'POST /api/notes'],
  ]) {
    const req = { ...base(), method, path, route };
    assert.equal(classifyResourceRoute(req)?.resourceId, 'note:collection');
    assert.equal((await decide(req)).decision, 'allow');
  }
});

test('A 자기 메모 읽기·수정은 허용하고 B의 같은 메모 요청은 거부한다', async () => {
  const { normal } = fixtureRequests();
  for (const method of ['GET', 'PUT']) {
    const own = { ...normal, requestId: randomUUID(), method, route: `${method} /notes/:id` };
    assert.equal((await decide(own)).decision, 'allow', method);
    for (const other of [
      { subjectId: 'other_learner_fixture' },
      { deviceId: 'b'.repeat(16) },
    ]) {
      const decision = await decide({ ...own, requestId: randomUUID(), ...other });
      assert.equal(decision.decision, 'deny', `${method} ${JSON.stringify(other)}`);
      assert.equal(decision.reasonCode, 'resource_access_denied');
    }
  }
  // The dynamic API route is valid for both users; the server, not this
  // stateless decider, must prevent B from reading A's stored owner_id.
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const req = { ...base(), method, path: `/api/notes/${id}`, route: `${method} /api/notes/:id` };
    assert.equal((await decide(req)).decision, 'allow', method);
    assert.equal((await decide({ ...req, subjectId: 'other_learner_fixture' })).decision, 'allow');
  }
});

test('허용되지 않은 구역·기능 경로는 거부한다', async () => {
  const invalid = [
    { method: 'PUT', path: `/api/notices/${id}`, route: 'PUT /api/notices/:id' },
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

test('일반 학생의 강사 공지 작성·수정은 역할 주장과 관계없이 거부한다', async () => {
  for (const [method, path, route] of [
    ['PUT', `/api/instructor-notices/${id}`, 'PUT /api/instructor-notices/:id'],
    ['POST', '/api/instructor-notices', 'POST /api/instructor-notices'],
  ]) {
    const request = { ...base(), method, path, route };
    const withSpoofedRole = { ...request, role: 'instructor', headers: { 'x-role': 'instructor' } };
    for (const req of [request, withSpoofedRole]) {
      assert.equal(classifyResourceRoute(req), null);
      assert.equal((await decide(req)).decision, 'deny');
    }
  }
  const read = { ...base(), path: '/api/instructor-notices', route: 'GET /api/instructor-notices' };
  assert.equal((await decide(read)).decision, 'allow');
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
  const { normal } = fixtureRequests();
  const risk = {
    ...normal,
    signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
    stepUp: { verified: false, authAgeSeconds: null },
  };
  assert.equal((await decide(risk)).decision, 'step_up');
  assert.equal((await decide({ ...risk, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
});

test('경로 모양만 같은 다른 사용자의 개별 메모는 열지 않는다', () => {
  const subjectA = { ...base(), subjectId: 'anonymous_subject_A' };
  const subjectB = { ...base(), subjectId: 'anonymous_subject_B' };
  assert.equal(classifyResourceRoute(subjectA), null);
  assert.equal(classifyResourceRoute(subjectB), null);
  // 자료 API도 저장된 owner_id로 다시 확인한다.
});

test('동적 UUID 메모는 정확한 경로만 열고 기능 경로·쿼리·부정확한 라우트는 막는다', async () => {
  const own = { ...base(), method: 'GET', path: `/api/notes/${id}`, route: 'GET /api/notes/:id' };
  assert.deepEqual(classifyResourceRoute(own), { zone: 'note', resourceId: `note:${id}` });
  const malformed = [
    { path: '/api/notes/export' },
    { path: `/api/notes/${id}/export` },
    { path: `/api/notes/${id}/` },
    { path: `/api/notes/${id}?role=instructor` },
    { queryLength: 1 },
    { route: 'GET /api/notes' },
    { route: 'GET /api/notes/export' },
    { method: 'POST', route: 'POST /api/notes/:id' },
    { deviceId: 'not-a-verified-device' },
  ];
  for (const invalid of malformed) {
    const request = { ...own, ...invalid, requestId: randomUUID() };
    assert.equal((await decide(request)).decision, 'deny', JSON.stringify(invalid));
  }
  const unknown = { ...own, path: '/notes/another-learner', route: 'GET /notes/:id' };
  assert.equal((await decide(unknown)).decision, 'deny');
});
