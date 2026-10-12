import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runXdr } from '../scripts/xdr-run.mjs';

const script = new URL('../xdr/brute-force/decide.mjs', import.meta.url);
const demo = new URL('../xdr/fixtures/brute-force.demo.json', import.meta.url);

async function isolatedFixture(alerts, exercise) {
  const root = await mkdtemp(join(tmpdir(), 'official-xdr-'));
  try {
    await mkdir(join(root, 'xdr/fixtures'), { recursive: true });
    await mkdir(join(root, 'xdr/brute-force'), { recursive: true });
    await copyFile(script, join(root, 'xdr/brute-force/decide.mjs'));
    await writeFile(join(root, 'xdr/fixtures/brute-force.json'),
      JSON.stringify({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'brute-force', alerts }));
    return await exercise(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('official runner classifies original synthetic exercises without changing them', async () => {
  const doc = JSON.parse(await readFile(demo, 'utf8'));
  await isolatedFixture(doc.alerts, async root => {
    const report = await runXdr({ root, moduleKey: 'brute-force' });
    assert.equal(report.schema, 'aleph.xdr.result.v1');
    assert.equal(report.moduleKey, 'brute-force');
    assert.deepEqual(report.counts, { block: 3, alert: 2, record: 4 });
    assert.equal(report.decisions.length, 9);
    assert.ok(report.decisions.every(v =>
      Object.keys(v).join(',') === 'alertId,action,confidence,reason'));
    assert.equal(report.decisions[0].alertId, 'demo.001');
    const saved = JSON.parse(await readFile(join(root, 'xdr/brute-force/result.json'), 'utf8'));
    assert.deepEqual(saved, report);
    assert.doesNotMatch(JSON.stringify(report), /SECRET_DO_NOT_LOG|demo-user/);
  });
});

test('official runner safely downgrades invalid judge output to record', async () => {
  const alerts = [{ id: 'test-invalid', rule: { level: 8 }, data: { srcip: '192.0.2.70' } }];
  await isolatedFixture(alerts, async root => {
    await writeFile(join(root, 'xdr/brute-force/decide.mjs'),
      'export function decide() { return {action: "block", confidence: 999, reason: null}; }\n');
    const errors = [];
    const report = await runXdr({ root, moduleKey: 'brute-force', writeError: line => errors.push(line) });
    assert.deepEqual(report.counts, { block: 0, alert: 0, record: 1 });
    assert.deepEqual(report.decisions, [{
      alertId: 'test-invalid', action: 'record',
      confidence: 0, reason: '반환 형식이 아닙니다',
    }]);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /test-invalid/);
  });
});
