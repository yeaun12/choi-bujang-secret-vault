import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decide } from '../xdr/brute-force/decide.mjs';

const cases = [
  ['documented correlated SSH rule', { rule: { id: '5712', level: 10, frequency: 8, firedtimes: 1 }, data: { srcip: '198.51.100.10' } }, 'block'],
  ['same rule without source address', { rule: { id: '5712', level: 10 } }, 'alert'],
  ['same source, account, window with nine failures', { data: { srcip: '203.0.113.8' }, aggregation: { sameSourceIp: true, sameAccount: true, failedAttempts: 9, windowSeconds: 100 } }, 'block'],
  ['many accounts, confirmed repeated failures', { data: { srcip: '203.0.113.8' }, aggregation: { sameSourceIp: true, failedAttempts: 14, windowSeconds: 100, distinctAccounts: 6 } }, 'block'],
  ['ambiguous multi-account attempts', { data: { srcip: '203.0.113.8' }, aggregation: { sameSourceIp: true, failedAttempts: 6, windowSeconds: 240, distinctAccounts: 3 } }, 'alert'],
  ['correlation keywords without confirmed count', { rule: { description: 'SSH brute force alert', mitre: { id: ['T1110'] } }, data: { srcip: '203.0.113.8' } }, 'alert'],
  ['missing aggregation scope', { data: { srcip: '203.0.113.8' }, aggregation: { failedAttempts: 14, windowSeconds: 100, distinctAccounts: 6 } }, 'record'],
  ['high firedtimes is not same IP failure count', { rule: { id: '5710', level: 12, firedtimes: 300 }, data: { srcip: '198.51.100.10' } }, 'record'],
  ['one failed password', { rule: { level: 4, description: 'sshd: Failed password' }, data: { srcip: '192.0.2.9' } }, 'record'],
  ['successful normal login', { rule: { level: 3, description: 'Accepted password; successful login' }, data: { srcip: '192.0.2.9' } }, 'record'],
  ['null input', null, 'record'],
];

for (const [label, alert, expected] of cases) {
  test(label, () => {
    const result = decide(alert);
    assert.equal(result.action, expected);
    assert.deepEqual(Object.keys(result), ['action', 'confidence', 'reason']);
    assert.ok(result.confidence >= 0 && result.confidence <= 1);
    assert.equal(typeof result.reason, 'string');
    assert.ok(!result.reason.includes('\n'));
    assert.deepEqual(decide(alert), result, 'repeat calls must be deterministic');
  });
}

test('judge module has no imports, network, or file IO', () => {
  const source = readFileSync(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require)\s*\(/);
});
