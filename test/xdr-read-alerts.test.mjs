import test from 'node:test';
import assert from 'node:assert/strict';
import { projectAlerts } from '../xdr/brute-force/read-alerts.mjs';

test('one output per input and only five fields', () => {
  const alerts = [
    { timestamp: '2026-10-12T00:00:00Z', rule: { level: 10, description: 'Repeated authentication failures' }, data: { srcip: '198.51.100.1', dstuser: 'student', password: 'NEVER_PRINT_ME' } },
    { timestamp: '2026-10-12T00:01:00Z', rule: { level: 3, description: 'password=NEVER_PRINT_ME' }, data: { srcip: '203.0.113.1', srcuser: 'visitor' } },
  ];
  const rows = projectAlerts({ alerts });
  assert.equal(rows.length, alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.equal(rows[0].sourceAddress, '198.51.100.1');
  assert.equal(rows[0].account, 'student');
  assert.ok(!JSON.stringify(rows).includes('NEVER_PRINT_ME'));
});

test('never drops malformed entries', () => {
  const rows = projectAlerts([null, {}, { data: { win: { eventdata: { targetUserName: 'user' } } } }]);
  assert.equal(rows.length, 3);
  assert.equal(rows[2].account, 'user');
});

test('rejects unknown envelope', () => {
  assert.throws(() => projectAlerts({ invalid: [] }), TypeError);
});
