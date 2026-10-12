import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runBruteForce } from '../scripts/xdr-run.mjs';

async function sandbox(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-run-'));
  try { await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('synthetic replay yields separate block/alert/record counts and no normal blocks', async () => sandbox(async dir => {
  const resultPath = join(dir, 'result.json');
  const report = await runBruteForce({
    fixturePath: resolve('xdr/fixtures/brute-force.demo.json'),
    fixtureKind: 'synthetic',
    resultPath,
    stateDir: dir,
    now: '2026-10-12T03:00:00Z',
  });
  assert.equal(report.total, 9);
  assert.equal(report.extractedCount, 9);
  assert.deepEqual(report.counts, { block: 3, alert: 2, record: 4 });
  assert.deepEqual(report.responseCounts, { block: 3, alert: 2, record: 4 });
  assert.equal(report.labeledNormalCount, 4);
  assert.equal(report.normalBlockedCount, 0);
  assert.equal(report.judgeVerified, false);
  const json = JSON.parse(await readFile(resultPath, 'utf8'));
  assert.deepEqual(json.counts, report.counts);
  assert.equal(json.outcomes.length, json.total);
  assert.ok(!JSON.stringify(json).includes('demo-user'));
  const alertLog = await readFile(join(dir, 'alerts.log'), 'utf8');
  assert.equal(alertLog.trim().split('\n').length, 5);
  const denyList = JSON.parse(await readFile(join(dir, 'brute-force/deny-rules.json'), 'utf8'));
  assert.equal(denyList.rules.length, 3);
}));

test('without ground truth, normal event check is honestly unverifiable', async () => sandbox(async dir => {
  const fixturePath = join(dir, 'supplied.json');
  await writeFile(fixturePath, JSON.stringify([{
    id: 'external.1',
    rule: { description: 'successful login' },
    data: { srcip: '192.0.2.20' },
  }]));
  const report = await runBruteForce({
    fixturePath, resultPath: join(dir, 'result.json'), stateDir: dir, fixtureKind: 'provided-unverified',
  });
  assert.deepEqual(report.counts, { block: 0, alert: 0, record: 1 });
  assert.equal(report.normalBlockedCount, null);
  assert.equal(report.normalEventCheck, 'unverifiable-no-ground-truth');
}));
