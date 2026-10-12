import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/brute-force/decide.mjs';
import { runBruteForce } from '../scripts/xdr-run.mjs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const file = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
const course = JSON.parse(await readFile(file, 'utf8'));

test('matching teaching fixture: 28 events, without passwords or true identities', () => {
  assert.equal(course.schema, 'aleph.xdr.fixture.v1');
  assert.equal(course.moduleKey, 'brute-force');
  assert.equal(course.alerts.length, 28);
  assert.ok(course.alerts.every(a => /^user\d+$/.test(a.data?.srcuser)));
});

test('all 28 course examples classify as high-risk, uncertain, or routine', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [i, alert] of course.alerts.entries()) {
    const expected = i < 10 ? 'block' : i < 19 ? 'alert' : 'record';
    const result = decide(alert);
    assert.equal(result.action, expected, 'event ' + alert.id);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.equal(typeof result.reason, 'string');
    assert.ok(result.reason.length > 0 && !result.reason.includes('\n'));
    counts[result.action]++;
    // Never classify against known fixture event identifiers.
    assert.equal(decide({ ...alert, id: 'changed-id-' + i }).action, expected);
  }
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('all 28 alerts yield an official-shaped result document', async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'course-xdr-'));
  try {
    const report = await runBruteForce({
      fixturePath: resolve('xdr/fixtures/brute-force.json'),
      resultPath: join(stateDir, 'result.json'),
      stateDir,
      fixtureKind: 'course-shared-unverified',
      now: '2026-10-12T03:00:00.000Z',
    });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'brute-force');
    assert.deepEqual(report.counts, { block: 10, alert: 9, record: 9 });
    assert.equal(report.total, 28);
    assert.equal(report.decisions.length, 28);
    assert.equal(report.decisions[0].alertId, 'bf-01');
    assert.equal(report.decisions[27].alertId, 'bf-28');
    assert.deepEqual(report.responseCounts, { block: 10, alert: 9, record: 9 });
    assert.equal(report.judgeVerified, false);
    // No labels in the source means no verified false-positive rate for real deployments.
    assert.equal(report.normalBlockedCount, null);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('MITRE array and data.count numeric string are recognized without firedtimes', () => {
  const attack = structuredClone(course.alerts[0]);
  attack.id = 'other-id';
  delete attack.rule.firedtimes;
  assert.equal(decide(attack).action, 'block');
  const ambiguous = structuredClone(course.alerts[10]);
  ambiguous.id = 'other-id';
  assert.equal(decide(ambiguous).action, 'alert');
  const normal = structuredClone(course.alerts[19]);
  normal.id = 'other-id';
  assert.equal(decide(normal).action, 'record');
});

test('high rule level and firedtimes by themselves do not authorize a block', () => {
  const falsePositive = {
    rule: { id: '5710', level: 12, firedtimes: 100, mitre: ['T1110'], description: 'One isolated failed login' },
    data: { srcip: '192.0.2.80', count: '1' },
  };
  assert.notEqual(decide(falsePositive).action, 'block');
});
