import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdir, readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { decide } from '../xdr/web-injection/decide.mjs';
import { projectAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { runWebInjection } from '../scripts/xdr-run-web-injection.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';
import { isDenied } from '../xdr/web-injection/respond.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));
const checkCounts = { block: 8, alert: 9, record: 9 };

test('shared web-injection fixture is intact and all events are extracted', () => {
  assert.equal(fixture.schema, 'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey, 'web-injection');
  assert.equal(fixture.alerts.length, 26);
  const projected = projectAlerts(fixture);
  assert.equal(projected.length, 26);
  assert.deepEqual(Object.keys(projected[0]),
    ['timestamp', 'sourceAddress', 'requestUrl', 'ruleLevel', 'description']);
});

test('26 course event decisions distinguish repeated attacks, ambiguous and routine', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const [i, alert] of fixture.alerts.entries()) {
    const expected = i < 8 ? 'block' : i < 17 ? 'alert' : 'record';
    const output = decide(alert);
    assert.equal(output.action, expected, alert.id);
    assert.equal(output.action, decide({ ...alert, id: 'unrelated-' + i }).action,
      'must not memorize fixture IDs');
    assert.ok(output.confidence >= 0 && output.confidence <= 1);
    assert.equal(output.action, output.confidence >= 0.85 ? 'block' :
      output.confidence >= 0.5 ? 'alert' : 'record');
    assert.equal(typeof output.reason, 'string');
    counts[output.action]++;
  }
  assert.deepEqual(counts, checkCounts);
});

test('normal text and one-off SQL or script words are not blocked', () => {
  for (const url of ['/search?q=select-course', '/search?q=script-class',
    '/files?path=up-notes', '/search?q=sql-class-notice']) {
    assert.equal(decide({
      rule: { level: 3, mitre: [], description: 'Normal user query' },
      data: { srcip: '192.0.2.90', url, count: '1' },
    }).action, 'record');
  }
  assert.equal(decide({
    rule: { level: 12, mitre: ['T1190'], description: 'SQL 수업 공지를 반복 조회했습니다.' },
    data: { srcip: '192.0.2.90', url: '/search?q=sql-class', count: '20' },
  }).action, 'alert');
});

test('no inferred repetitive count from firedtimes alone', () => {
  const flagged = {
    rule: { level: 12, mitre: ['T1190'], firedtimes: 900, description: 'SQL 구문 주입 표기가 반복됐습니다.' },
    data: { srcip: '192.0.2.90', url: '/search?q=doc-sql-chain' },
  };
  assert.notEqual(decide(flagged).action, 'block');
  assert.equal(decide({ ...flagged, data: { ...flagged.data, count: '12' } }).action, 'block');
  assert.notEqual(decide({ ...flagged, data: { count: '12', url: '/search?q=doc-sql-chain' } }).action, 'block');
});

test('single alert decision is import-free and does not inspect secret values', async () => {
  const source = await readFile(new URL('../xdr/web-injection/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require)\s*\(/);
});

test('local replay produces 8/9/9, 15-minute expiry, and sanitized alerts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-web-'));
  try {
    const at = '2026-10-12T03:00:00Z';
    const resultPath = join(dir, 'result.json');
    const report = await runWebInjection({
      fixturePath: resolve('xdr/fixtures/web-injection.json'),
      resultPath, stateDir: dir, now: at,
    });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'web-injection');
    assert.equal(report.total, 26);
    assert.deepEqual(report.counts, checkCounts);
    assert.deepEqual(report.responseCounts, checkCounts);
    assert.equal(report.decisions.length, 26);
    assert.equal(report.decisions[0].alertId, 'wi-01');
    assert.equal(report.decisions[25].alertId, 'wi-26');
    assert.equal(report.judgeVerified, false);
    assert.equal(report.normalBlockedCount, null);
    const onDisk = JSON.parse(await readFile(resultPath, 'utf8'));
    assert.deepEqual(onDisk.counts, checkCounts);
    assert.equal(await isDenied('203.0.113.10', { stateDir: dir, now: at }), true);
    assert.equal(await isDenied('192.0.2.70', { stateDir: dir, now: at }), false);
    assert.equal(await isDenied('203.0.113.10',
      { stateDir: dir, now: '2026-10-12T03:15:00Z' }), false);
    const rules = JSON.parse(await readFile(join(dir, 'web-injection/deny-rules.json'), 'utf8'));
    assert.equal(rules.rules.length, 8);
    const log = await readFile(join(dir, 'alerts.log'), 'utf8');
    assert.equal(log.trim().split('\n').length, 17);
    assert.doesNotMatch(log, /\/search\?|\/notes\?|password=|authorization:|token=/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('unaltered official runner classifies 26 course events in isolated directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'official-xdr-web-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/web-injection'), { recursive: true });
    await writeFile(join(root, 'xdr/fixtures/web-injection.json'), JSON.stringify(fixture));
    await copyFile(new URL('../xdr/web-injection/decide.mjs', import.meta.url),
      join(root, 'xdr/web-injection/decide.mjs'));
    const report = await runXdr({ root, moduleKey: 'web-injection' });
    assert.deepEqual(Object.keys(report), ['schema', 'moduleKey', 'decisions', 'counts']);
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.deepEqual(report.counts, checkCounts);
    assert.equal(report.decisions.length, 26);
    const saved = JSON.parse(await readFile(join(root, 'xdr/web-injection/result.json'), 'utf8'));
    assert.deepEqual(saved, report);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
