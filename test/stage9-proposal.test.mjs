import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detect.mjs';

const start = Date.parse('2026-10-01T00:00:00.000Z');
const events = (count, { subject = 'learner_fixture', seconds = 2,
  from = start, method = 'GET' } = {}) =>
  Array.from({ length: count }, (_, index) => ({
    at: new Date(from + index * seconds * 1000).toISOString(),
    method, identity: { sub: subject },
  }));

test('stage 9 task 3: only over-threshold reads propose revocation', () => {
  assert.deepEqual(detect(events(120)), { action: 'observe' });
  assert.deepEqual(detect(events(121)), {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: 'learner_fixture',
  });
  assert.deepEqual(detect(events(200)), {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: 'learner_fixture',
  });
});

test('stage 9 task 3: different subjects, read windows and methods stay separate', () => {
  assert.deepEqual(detect([...events(100), ...events(100, { subject: 'other_fixture' })]),
    { action: 'observe' });
  assert.deepEqual(detect(events(200, { seconds: 7 })), { action: 'observe' });
  assert.deepEqual(detect(events(180, { method: 'POST' })), { action: 'observe' });
});

test('stage 9 task 3: unverified device/network/role cannot select a revocation target', () => {
  const tampered = events(121).map(e => ({
    ...e, network: 'unusual', deviceId: 'claimed-device',
    token: 'not-retained', identity: { sub: 'learner_fixture', role: 'instructor' },
  }));
  const result = detect(tampered);
  assert.deepEqual(result, {
    action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture',
  });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
  assert.ok(!JSON.stringify(result).includes('claimed-device'));
  assert.ok(!JSON.stringify(result).includes('not-retained'));
  assert.deepEqual(detect([{
    at: new Date(start).toISOString(), method: 'GET',
    identity: { sub: 'learner_fixture' }, network: 'unusual', deviceId: 'claimed-device',
  }]), { action: 'observe' });
});
