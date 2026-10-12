import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { respond, isDenied } from '../xdr/brute-force/respond.mjs';

const NOW = '2026-10-12T03:00:00.000Z';
const suspicious = { id: '1760000000.1', rule: { id: '5712', description: 'SSH multiple authentication failures' }, data: { srcip: '198.51.100.11', dstuser: 'user1', password: 'SECRET_DO_NOT_LOG' } };
const block = { action: 'block', confidence: 0.97, reason: 'wazuh_correlated_ssh_brute_force' };
const alert = { action: 'alert', confidence: 0.70, reason: 'repeated_failures_same_source_and_account' };
const record = { action: 'record', confidence: 0.10, reason: 'no_matching_pattern' };

async function sandbox(fn) {
  const stateDir = await mkdtemp(join(tmpdir(), 'xdr-respond-'));
  try { await fn({ stateDir, now: NOW }); } finally { await rm(stateDir, { recursive: true, force: true }); }
}

test('confirmed candidate staged temporarily and normal source unaffected', async () => sandbox(async opts => {
  const output = await respond(suspicious, block, opts);
  assert.equal(output.action, 'block');
  assert.equal(output.stagedBlock, true);
  assert.equal(output.evidenceAlertId, suspicious.id);
  assert.equal(output.expiresAt, '2026-10-12T03:15:00.000Z');
  assert.equal(await isDenied('198.51.100.11', opts), true);
  assert.equal(await isDenied('198.51.100.12', opts), false);
  assert.equal(await isDenied('198.51.100.11', { ...opts, now: '2026-10-12T03:15:00.000Z' }), false);
  const rules = JSON.parse(await readFile(join(opts.stateDir, 'brute-force/deny-rules.json'), 'utf8'));
  assert.equal(rules.rules.length, 1);
  assert.equal(rules.rules[0].evidenceAlertId, suspicious.id);
  const log = await readFile(join(opts.stateDir, 'alerts.log'), 'utf8');
  assert.equal(log.trim().split('\n').length, 1);
  assert.doesNotMatch(log, /SECRET_DO_NOT_LOG|user1/);
}));

test('ambiguous case logs alert but does not create deny rule', async () => sandbox(async opts => {
  assert.equal((await respond(suspicious, alert, opts)).action, 'alert');
  assert.equal(await isDenied('198.51.100.11', opts), false);
}));

test('normal event records only, no alert or deny', async () => sandbox(async opts => {
  assert.equal((await respond({ id: 'normal.1', rule: { description: 'successful login' }, data: { srcip: '198.51.100.12' } }, record, opts)).action, 'record');
  assert.equal(await isDenied('198.51.100.12', opts), false);
}));

test('safety: explicit success is never blocked even if response says block', async () => sandbox(async opts => {
  const output = await respond({ ...suspicious, rule: { description: 'successful login' } }, block, opts);
  assert.equal(output.action, 'alert');
  assert.equal(await isDenied('198.51.100.11', opts), false);
}));

test('safety: no source IP or evidence ID means no block', async () => sandbox(async opts => {
  assert.equal((await respond({ ...suspicious, id: null }, block, opts)).action, 'alert');
  assert.equal((await respond({ ...suspicious, data: {} }, block, opts)).action, 'alert');
  assert.equal(await isDenied('198.51.100.11', opts), false);
}));

test('duplicate confirmed alert does not create duplicate denial', async () => sandbox(async opts => {
  await respond(suspicious, block, opts);
  await respond(suspicious, block, opts);
  const rules = JSON.parse(await readFile(join(opts.stateDir, 'brute-force/deny-rules.json'), 'utf8'));
  assert.equal(rules.rules.length, 1);
}));
