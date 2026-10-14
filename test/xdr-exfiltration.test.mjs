import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));

test('shared exfiltration fixture is unchanged and contains 30 synthetic events', () => {
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'exfiltration');
  assert.equal(fixture.alerts.length, 30);
  assert.ok(fixture.alerts.every(a => /^ex-\d{2}$/.test(a.id)));
});

test('all 30 events classify 10 block, 10 alert, 10 record without using IDs', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [i, entry] of fixture.alerts.entries()) {
    const expected = i < 10 ? 'block' : i < 20 ? 'alert' : 'record';
    const decision = decide(entry);
    assert.equal(decision.action, expected, entry.id);
    assert.equal(decide({ ...entry, id: 'renamed-' + i }).action, expected);
    assert.ok(Number.isFinite(decision.confidence) &&
      decision.confidence >= 0 && decision.confidence <= 1);
    assert.equal(typeof decision.reason, 'string');
    assert.ok(decision.reason.length > 0 && decision.reason.length < 200);
    assert.equal(decision.action, decision.confidence >= 0.85 ? 'block' :
      decision.confidence >= 0.5 ? 'alert' : 'record');
    counts[decision.action]++;
  }
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
});

test('large legitimate transfer and a high severity alone do not trigger block', () => {
  const benign = {
    rule: { level: 13, mitre: ['T1048'], description: '승인된 백업을 처음 보는 목적지로 200건 전송했습니다.' },
    data: {
      srcip: '192.0.2.9', srcuser: 'svc-lab', dstip: '198.51.100.9',
      bytes: '1000000000', files: '200',
    },
  };
  assert.notEqual(decide(benign).action, 'block');
  const largeOnly = {
    ...benign,
    rule: { level: 13, mitre: ['T1048'], description: 'Large ordinary file transfer completed.' },
  };
  assert.notEqual(decide(largeOnly).action, 'block');
  assert.equal(decide(fixture.alerts[22]).action, 'record');
});

test('missing transfer corroboration never blocks', () => {
  const entry = structuredClone(fixture.alerts[0]);
  for (const key of ['srcip', 'srcuser', 'dstip', 'bytes']) {
    const altered = structuredClone(entry);
    delete altered.data[key];
    assert.notEqual(decide(altered).action, 'block', key);
  }
  const noMitre = structuredClone(entry);
  noMitre.rule.mitre = [];
  assert.notEqual(decide(noMitre).action, 'block');
  const sameAddress = structuredClone(entry);
  sameAddress.data.dstip = sameAddress.data.srcip;
  assert.notEqual(decide(sameAddress).action, 'block');
});

test('a firedtimes counter cannot replace correlated transfer count', () => {
  const entry = structuredClone(fixture.alerts[2]); // Repeated bulk transfers
  delete entry.data.count;
  entry.rule.firedtimes = 900;
  assert.notEqual(decide(entry).action, 'block');
  assert.equal(decide({ ...entry, data: { ...entry.data, count: '8' } }).action, 'block');
});

test('failed or nonexistent external transfers do not block', () => {
  const failed = structuredClone(fixture.alerts[0]);
  failed.rule.description = '10분 안에 자료 200건이 처음 보는 목적지로 전송 실패했습니다.';
  failed.data.bytes = '0';
  assert.notEqual(decide(failed).action, 'block');
  assert.notEqual(decide(fixture.alerts[12]).action, 'block'); // No external destination
  assert.equal(decide(null).action, 'record');
  assert.equal(decide([]).action, 'record');
  assert.equal(decide({ rule: {}, data: {} }).action, 'record');
});

test('isolated judge module contains no imports or outgoing calls', async () => {
  const source = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('the independent offline runner produces the official 10/10/10 result', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-exfil-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/exfiltration'), { recursive: true });
    await writeFile(join(root, 'xdr/fixtures/exfiltration.json'), JSON.stringify(fixture));
    await copyFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url),
      join(root, 'xdr/exfiltration/decide.mjs'));
    const report = await runXdr({ root, moduleKey: 'exfiltration' });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'exfiltration');
    assert.deepEqual(report.counts, { block: 10, alert: 10, record: 10 });
    assert.equal(report.decisions.length, 30);
    assert.deepEqual(Object.keys(report), ['schema', 'moduleKey', 'decisions', 'counts']);
    const saved = JSON.parse(await readFile(join(root, 'xdr/exfiltration/result.json'), 'utf8'));
    assert.deepEqual(saved, report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
