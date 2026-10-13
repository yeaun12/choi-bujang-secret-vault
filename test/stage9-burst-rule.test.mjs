import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect, findReadBurstCandidate } from '../src/detect.mjs';

const START = Date.parse('2026-10-01T00:00:00.000Z');
const reads = (count, { subject = 'learner_fixture', spacing = 2000, start = START,
  method = 'GET' } = {}) =>
  Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * spacing).toISOString(), method,
    identity: { sub: subject },
  }));

test('stage 9 task 2: exactly 120 is normal, 121 is burst candidate', () => {
  assert.equal(findReadBurstCandidate(reads(30)), null);
  assert.equal(findReadBurstCandidate(reads(120)), null);
  assert.deepEqual(findReadBurstCandidate(reads(121)), {
    subject: 'learner_fixture', reasonCode: 'burst_read',
  });
  assert.deepEqual(findReadBurstCandidate(reads(200)), {
    subject: 'learner_fixture', reasonCode: 'burst_read',
  });
});

test('stage 9 task 2: never combine different subjects, POSTs, or out-of-window reads', () => {
  const separate = [...reads(100), ...reads(100, { subject: 'other_fixture' })];
  assert.equal(findReadBurstCandidate(separate), null);
  assert.equal(findReadBurstCandidate(reads(200, { spacing: 7000 })), null);
  assert.equal(findReadBurstCandidate([...reads(100), ...reads(100, { method: 'POST' })]), null);
  assert.equal(findReadBurstCandidate(reads(200, { method: 'POST' })), null);
});

test('stage 9 task 2: use a rolling 10-minute window, irrespective of event order', () => {
  const staggered = reads(61, { spacing: 1000, start: START })
    .concat(reads(60, { spacing: 1000, start: START + 4 * 60 * 1000 }));
  assert.deepEqual(findReadBurstCandidate(staggered.reverse()), {
    subject: 'learner_fixture', reasonCode: 'burst_read',
  });

  // Window [0, 10min) cannot include both of these distant bursts.
  const farApart = [...reads(70, { spacing: 1000, start: START }),
    ...reads(70, { spacing: 1000, start: START + 12 * 60 * 1000 })];
  assert.equal(findReadBurstCandidate(farApart), null);
});

test('stage 9 task 2: the first threshold-crossing subject is deterministic', () => {
  const earlier = reads(121, { subject: 'early_subject', spacing: 1000, start: START });
  const later = reads(121, { subject: 'late_subject', spacing: 1000, start: START + 180000 });
  assert.deepEqual(findReadBurstCandidate([...later, ...earlier]), {
    subject: 'early_subject', reasonCode: 'burst_read',
  });
});

test('stage 9 task 2: spoofed network/device metadata is never considered trusted', () => {
  const tampered = reads(121).map(event => ({
    ...event, network: 'unusual', deviceId: 'not-verified',
    identity: { ...event.identity, role: 'admin' }, token: 'not-retained',
  }));
  assert.deepEqual(findReadBurstCandidate(tampered), {
    subject: 'learner_fixture', reasonCode: 'burst_read',
  });
  // Only the verified subject and burst count determine the practice proposal.
  // No unverified device is revoked; spoofed network/device strings are ignored.
  assert.deepEqual(detect(tampered), {
    action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture',
  });
  assert.deepEqual(detect(reads(30)), { action: 'observe' });
});
