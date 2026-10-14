import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/persistence/decide.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));

test('course persistence data: 24 fixtures remain unchanged', () => {
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'persistence');
  assert.equal(fixture.alerts.length, 24);
  assert.ok(fixture.alerts.every(a => /^ps-\d{2}$/.test(a.id)));
});

test('every persistence alert is independently classified without memorizing fixture IDs', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [index, alert] of fixture.alerts.entries()) {
    const expected = index < 8 ? 'block' : index < 16 ? 'alert' : 'record';
    const decision = decide(alert);
    assert.equal(decision.action, expected, alert.id);
    assert.equal(decide({ ...alert, id: 'unrelated-' + index }).action, expected);
    assert.equal(decision.action, decision.confidence >= 0.85 ? 'block' :
      decision.confidence >= 0.5 ? 'alert' : 'record');
    assert.equal(typeof decision.reason, 'string');
    assert.ok(decision.reason.length > 0 && decision.reason.length < 200);
    counts[decision.action]++;
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
});

test('MITRE tag and high severity without corroborated change never block', () => {
  const high = {
    rule: { level: 12, mitre: ['T1543'], description: 'Routine service status query' },
    data: { srcip: '192.0.2.90', path: 'C:\\Windows\\System32\\service.exe' },
  };
  assert.notEqual(decide(high).action, 'block');
  const tempOnly = {
    ...high,
    rule: { ...high.rule, description: '임시 폴더에 실행 파일이 있습니다. 서비스 등록은 없습니다.' },
    data: { srcip: '192.0.2.90', path: 'C:\\Users\\user01\\AppData\\Local\\Temp\\draft.exe' },
  };
  assert.notEqual(decide(tempOnly).action, 'block');
  const noMitre = { ...fixture.alerts[0], rule: { ...fixture.alerts[0].rule, mitre: [] } };
  assert.notEqual(decide(noMitre).action, 'block');
});

test('missing source, count and temporary executable each prevent overconfident blocks', () => {
  const one = structuredClone(fixture.alerts[0]);
  delete one.data.srcip;
  assert.notEqual(decide(one).action, 'block');

  const repeated = structuredClone(fixture.alerts[3]);
  delete repeated.data.count;
  repeated.rule.firedtimes = 50;
  assert.notEqual(decide(repeated).action, 'block');

  const changedFile = structuredClone(fixture.alerts[5]);
  changedFile.data.path = 'C:\\Program Files\\class-tool\\signed.exe';
  assert.notEqual(decide(changedFile).action, 'block');
});

test('normal signed service remains record and malformed input never throws', () => {
  assert.equal(decide(fixture.alerts[18]).action, 'record');
  assert.equal(decide(null).action, 'record');
  assert.equal(decide([]).action, 'record');
  assert.equal(decide({ rule: {}, data: {} }).action, 'record');
  assert.equal(decide({ rule: { level: 'NaN', mitre: 'T1543' } }).action, 'record');
});

test('isolated decision file has no imports, file operations or outgoing requests', async () => {
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('offline XDR runner writes only the official-shaped 8/8/8 result', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-persistence-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/persistence'), { recursive: true });
    await writeFile(join(root, 'xdr/fixtures/persistence.json'), JSON.stringify(fixture));
    await copyFile(new URL('../xdr/persistence/decide.mjs', import.meta.url),
      join(root, 'xdr/persistence/decide.mjs'));
    const report = await runXdr({ root, moduleKey: 'persistence' });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'persistence');
    assert.deepEqual(report.counts, { block: 8, alert: 8, record: 8 });
    assert.equal(report.decisions.length, 24);
    assert.deepEqual(Object.keys(report), ['schema', 'moduleKey', 'decisions', 'counts']);
    const saved = JSON.parse(await readFile(join(root, 'xdr/persistence/result.json'), 'utf8'));
    assert.deepEqual(saved, report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
