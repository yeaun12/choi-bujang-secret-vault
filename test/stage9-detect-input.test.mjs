import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect, readDetectionEvents } from '../src/detect.mjs';

const event = (overrides = {}) => ({
  at: '2026-10-01T00:00:00.000Z',
  method: 'GET',
  identity: { sub: 'learner_fixture' },
  ...overrides,
});

test('stage 9 task 1: valid practice events normalize into approved fields', () => {
  const normalized = readDetectionEvents([event(), event({ method: 'POST' })]);
  assert.deepEqual(normalized, [
    { atMs: Date.parse('2026-10-01T00:00:00.000Z'), method: 'GET', subject: 'learner_fixture' },
    { atMs: Date.parse('2026-10-01T00:00:00.000Z'), method: 'POST', subject: 'learner_fixture' },
  ]);
  assert.deepEqual(detect([event()]), { action: 'observe' });
  assert.deepEqual(detect(Array.from({ length: 121 }, () => event())), {
    action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture',
  });
});

test('stage 9 task 1: untrusted metadata never enters normalized output', () => {
  const source = event({ identity: { sub: 'learner_fixture', email: 'not-retained' }, token: 'not-retained',
    body: 'not-retained', name: 'not-retained', deviceId: 'not-contractual',
    decision: 'not-contractual', network: 'not-contractual' });
  const output = readDetectionEvents([source]);
  assert.deepEqual(Object.keys(output[0]).sort(), ['atMs', 'method', 'subject']);
  assert.ok(!JSON.stringify(output).includes('not-retained'));
  assert.ok(!JSON.stringify(output).includes('not-contractual'));
});

test('stage 9 task 1: malformed events reject with non-sensitive error', () => {
  const invalid = [null, {}, [], event({ method: 'get' }), event({ at: 'nonsense' }),
    event({ identity: {} }), event({ identity: { sub: '' } }),
    event({ identity: { sub: 'x'.repeat(257) } })];
  for (const value of invalid) {
    assert.throws(() => readDetectionEvents([value]), (error) =>
      error instanceof TypeError && error.message === 'invalid_detection_event');
  }
  assert.throws(() => detect({ not: 'events' }), { message: 'invalid_detection_events' });
});
