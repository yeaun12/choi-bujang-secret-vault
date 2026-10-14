import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { projectAlerts, readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { decide as decidePersistence } from '../xdr/persistence/decide.mjs';
import { respond, isDenied, enforceZtnaDecision } from '../xdr/persistence/respond.mjs';
import { replayPersistence } from '../scripts/xdr-run-persistence.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
const NOW = '2026-10-14T02:00:00.000Z';
const local = async fn => {
  const stateDir = await mkdtemp(join(tmpdir(), 'xdr04-checkpoint-'));
  try { return await fn({ stateDir, now: NOW }); }
  finally { await rm(stateDir, { recursive: true, force: true }); }
};

test('production contract and unchanged fixture: 24 events projected to exactly five safe fields', async () => {
  assert.equal(fixture.alerts.length, 24);
  assert.equal(fixture.moduleKey, 'persistence');
  const rows = projectAlerts(fixture);
  assert.deepEqual(rows, await readAlerts('xdr/fixtures/persistence.json'));
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]),
    ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.equal(rows[0].account, 'user01');
  assert.equal(rows[0].ruleLevel, 12);
  assert.ok(!Object.hasOwn(rows[0], 'path'));
});

test('projection redacts injected secret-looking text and emits no raw credentials', () => {
  const rows = projectAlerts([{ timestamp: '2026-09-27T09:00:00Z',
    rule: { level: 12, description: '서비스 password=SECRET123 token=HIDDEN456 Bearer ABCDEF' },
    data: { srcip: '192.0.2.8', srcuser: 'user01', password: 'SENSITIVE_BLOB' },
  }]);
  const serialized = JSON.stringify(rows);
  for (const secret of ['SECRET123', 'HIDDEN456', 'ABCDEF', 'SENSITIVE_BLOB']) {
    assert.ok(!serialized.includes(secret));
  }
  assert.equal(projectAlerts([null]).length, 1);
  assert.throws(() => projectAlerts({ unknown: true }), TypeError);
});

test('three MITRE patterns each include a condition and a one-line rationale matching the isolated module', async () => {
  const data = JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8'));
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.equal(data.patterns.length, 3);
  for (const p of data.patterns) {
    assert.ok(p.name && p.condition && p.rationale && !p.rationale.includes('\n'));
    assert.ok(source.includes(p.name));
    assert.ok(source.includes(p.rationale));
  }
  assert.doesNotMatch(source, /(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source, /\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('confirmed persistence candidate staged with 15-minute expiry and evidence alert ID', async () =>
  local(async opts => {
    const a = fixture.alerts[0];
    const out = await respond(a, decidePersistence(a), opts);
    assert.equal(out.action, 'block');
    assert.equal(out.stagedBlock, true);
    assert.equal(out.evidenceAlertId, a.id);
    assert.equal(out.expiresAt, '2026-10-14T02:15:00.000Z');
    assert.equal(await isDenied(a.data.srcip, opts), true);
    assert.equal(await isDenied('192.0.2.74', opts), false);
    assert.equal(await isDenied(a.data.srcip, { ...opts, now: out.expiresAt }), false);
    const rules = JSON.parse(await readFile(join(opts.stateDir, 'persistence/deny-rules.json'), 'utf8'));
    assert.equal(rules.rules.length, 1);
    assert.equal(rules.rules[0].evidenceAlertId, a.id);
    assert.equal(rules.rules[0].ruleId, 'xdr-04:' + a.id);
    const log = await readFile(join(opts.stateDir, 'alerts.log'), 'utf8');
    assert.equal(log.trim().split('\n').length, 1);
    assert.doesNotMatch(log, /AppData|user01|helper\.exe|password|token/i);
  }));

test('uncertain event alerts only and forged block cannot quarantine normal event', async () =>
  local(async opts => {
    const uncertain = fixture.alerts[8];
    const normal = fixture.alerts[16];
    assert.equal((await respond(uncertain, decidePersistence(uncertain), opts)).action, 'alert');
    assert.equal((await respond(normal,
      { action: 'block', confidence: 0.99, reason: 'fake_evidence' }, opts)).action, 'record');
    assert.equal(await isDenied(uncertain.data.srcip, opts), false);
    assert.equal(await isDenied(normal.data.srcip, opts), false);
    const log = await readFile(join(opts.stateDir, 'alerts.log'), 'utf8');
    assert.equal(log.trim().split('\n').length, 1);
    await assert.rejects(readFile(join(opts.stateDir, 'persistence/deny-rules.json'), 'utf8'),
      error => error?.code === 'ENOENT');
  }));

test('suspicious alert without source or evidence ID cannot stage a block', async () =>
  local(async opts => {
    const a = fixture.alerts[0];
    const noSource = { ...a, data: { ...a.data } };
    delete noSource.data.srcip;
    assert.equal((await respond(noSource, { action: 'block', confidence: 0.97 }, opts)).stagedBlock, false);
    assert.equal((await respond({ ...a, id: null }, decidePersistence(a), opts)).stagedBlock, false);
    assert.equal(await isDenied(a.data.srcip, opts), false);
  }));

test('repeated same evidence updates rather than duplicating staged rules', async () =>
  local(async opts => {
    const a = fixture.alerts[0];
    await respond(a, decidePersistence(a), opts);
    await respond(a, decidePersistence(a), opts);
    const rules = JSON.parse(await readFile(join(opts.stateDir, 'persistence/deny-rules.json'), 'utf8'));
    assert.equal(rules.rules.length, 1);
    assert.equal(rules.rules[0].ruleId, 'xdr-04:ps-01');
  }));

test('original ZTNA decision is preserved for normal requests, denied only by trusted IP adapter', async () =>
  local(async opts => {
    const base = await decideZtna({
      schema: 'aleph.decision.v1', requestId: 'local-fixture',
      classId: 'class_fixture', projectId: 'project_fixture',
      subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
      service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
      queryLength: 0, querySha256: '', deviceRegistered: true,
      stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
      signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 9 },
    });
    assert.equal(base.decision, 'allow');
    const a = fixture.alerts[0];
    await respond(a, decidePersistence(a), opts);
    const out = await enforceZtnaDecision(base, a.data.srcip, opts);
    assert.deepEqual(Object.keys(out), ['schema', 'requestId', 'decision', 'reasonCode', 'ruleIds']);
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'resource_access_denied');
    assert.deepEqual(out.ruleIds, ['resource_scope']);
    assert.equal((await enforceZtnaDecision(base, '192.0.2.74', opts)).decision, 'allow');
    const existingDeny = { ...base, decision: 'deny', reasonCode: 'device_not_registered' };
    assert.deepEqual(await enforceZtnaDecision(existingDeny, '192.0.2.74', opts), existingDeny);
    assert.equal(base.decision, 'allow', 'must not mutate original ZTNA result');
  }));

test('synthetic replay classifies 8/8/8, stages only confirmed attacks, zero routine IP denies', async () =>
  local(async opts => {
    const r = await replayPersistence({ fixturePath: 'xdr/fixtures/persistence.json', ...opts });
    assert.equal(r.total, 24);
    assert.equal(r.extractedCount, 24);
    assert.deepEqual(r.counts, { block: 8, alert: 8, record: 8 });
    assert.deepEqual(r.responseCounts, r.counts);
    assert.equal(r.stagedBlocks, 8);
    assert.equal(r.normalBlockedCount, 0);
    assert.equal(r.judgeVerified, false);
    const rules = JSON.parse(await readFile(join(opts.stateDir, 'persistence/deny-rules.json'), 'utf8'));
    assert.equal(rules.rules.length, 8);
    const log = await readFile(join(opts.stateDir, 'alerts.log'), 'utf8');
    assert.equal(log.trim().split('\n').length, 16);
    for (const alert of fixture.alerts.slice(16)) {
      assert.equal(await isDenied(alert.data.srcip, opts), false, alert.id);
    }
    assert.doesNotMatch(log, /AppData|\\Users\\|password=|token=/i);
  }));
