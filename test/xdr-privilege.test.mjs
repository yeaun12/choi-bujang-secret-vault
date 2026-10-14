import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, copyFile, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/privilege/decide.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));

test('shared privilege fixture remains intact with 26 synthetic events', () => {
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'privilege');
  assert.equal(fixture.alerts.length, 26);
  assert.ok(fixture.alerts.every(a => /^pv-\d{2}$/.test(a.id)));
});

test('privilege classifier distinguishes 9 attacks, 8 uncertain, 9 routine', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [i, a] of fixture.alerts.entries()) {
    const expected = i < 9 ? 'block' : i < 17 ? 'alert' : 'record';
    const out = decide(a);
    assert.equal(out.action, expected, a.id);
    assert.equal(decide({ ...a, id: 'changed-' + i }).action, expected,
      'must not memorize alert IDs');
    assert.equal(typeof out.reason, 'string');
    assert.ok(out.reason.length > 0 && out.reason.length < 200);
    assert.ok(Number.isFinite(out.confidence) && out.confidence >= 0 && out.confidence <= 1);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' :
      out.confidence >= 0.5 ? 'alert' : 'record');
    counts[out.action]++;
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
});

test('routine administrator actions and high MITRE tags alone do not block', () => {
  const benign = {
    rule: { level: 13, mitre: ['T1078'], description: 'Approved administrator group membership query' },
    data: { srcip: '192.0.2.70', srcuser: 'admin01', group: 'administrators' },
  };
  assert.notEqual(decide(benign).action, 'block');
  assert.equal(decide(fixture.alerts[20]).action, 'record');
  const projectGroup = {
    ...fixture.alerts[0],
    data: { ...fixture.alerts[0].data, group: 'project-week3' },
  };
  assert.notEqual(decide(projectGroup).action, 'block');
});

test('missing source, user, trusted technique or event count prevents overconfident blocks', () => {
  const original = structuredClone(fixture.alerts[0]);
  delete original.data.srcip;
  assert.notEqual(decide(original).action, 'block');
  const missingUser = structuredClone(fixture.alerts[0]);
  delete missingUser.data.srcuser;
  assert.notEqual(decide(missingUser).action, 'block');
  const noTag = structuredClone(fixture.alerts[1]);
  noTag.rule.mitre = [];
  assert.notEqual(decide(noTag).action, 'block');
  const bulk = structuredClone(fixture.alerts[4]);
  delete bulk.data.count;
  bulk.rule.firedtimes = 400;
  assert.notEqual(decide(bulk).action, 'block');
});

test('cancelled or failed escalation and missing input never produce block', () => {
  const cancelled = structuredClone(fixture.alerts[1]);
  cancelled.rule.description = '방금 관리자가 된 user01 이 관리자 명령 실행을 취소했습니다.';
  assert.notEqual(decide(cancelled).action, 'block');
  assert.equal(decide(null).action, 'record');
  assert.equal(decide([]).action, 'record');
  assert.equal(decide({ rule: {}, data: {} }).action, 'record');
  assert.equal(decide({ rule: { level: 'bad', mitre: [] } }).action, 'record');
});

test('judge entry is self-contained and has no file/network/secret dependency', async () => {
  const source = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('offline judge-style replay produces only the official result fields', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-privilege-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/privilege'), { recursive: true });
    await writeFile(join(root, 'xdr/fixtures/privilege.json'), JSON.stringify(fixture));
    await copyFile(new URL('../xdr/privilege/decide.mjs', import.meta.url),
      join(root, 'xdr/privilege/decide.mjs'));
    const report = await runXdr({ root, moduleKey: 'privilege' });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'privilege');
    assert.deepEqual(report.counts, { block: 9, alert: 8, record: 9 });
    assert.equal(report.decisions.length, 26);
    assert.deepEqual(Object.keys(report), ['schema', 'moduleKey', 'decisions', 'counts']);
    const saved = JSON.parse(await readFile(join(root, 'xdr/privilege/result.json'), 'utf8'));
    assert.deepEqual(saved, report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
