import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, rmSync } from 'node:fs';
import {
  CONFIRMATION, applyTestPolicyRestore, checkRestoredTestPolicy,
  prepareDemoTestPolicy, previewTestPolicyRestore, testPolicyPaths,
} from '../scripts/stage10-policy-restore.mjs';

function newSlot() { return 'test-' + randomBytes(4).toString('hex'); }
function cleanup(slot) {
  const paths = testPolicyPaths(slot);
  rmSync(paths.candidate, { force: true });
  rmSync(paths.audit, { force: true });
}

test('stage 10 task 2: preview is read-only and requires an existing test file', () => {
  const slot = newSlot();
  try {
    assert.throws(() => previewTestPolicyRestore(slot));
    const created = prepareDemoTestPolicy(slot);
    assert.ok(created.file.startsWith('.stage10-sandbox/'));
    const before = readFileSync(testPolicyPaths(slot).candidate, 'utf8');
    const preview = previewTestPolicyRestore(slot);
    const after = readFileSync(testPolicyPaths(slot).candidate, 'utf8');
    assert.equal(before, after);
    assert.equal(preview.matchesBackup, false);
    assert.ok(preview.addedLines > 0 && preview.removedLines > 0);
    assert.deepEqual(preview.affects, [created.file]);
    assert.equal(preview.changesProductionPolicy, false);
    assert.equal(preview.changesDatabase, false);
  } finally { cleanup(slot); }
});

test('stage 10 task 2: requires preview hash and explicit test-only approval', () => {
  const slot = newSlot();
  try {
    prepareDemoTestPolicy(slot);
    const plan = previewTestPolicyRestore(slot);
    assert.throws(() => applyTestPolicyRestore({
      slot, expectedCurrentSha256: plan.currentSha256, confirmation: 'YES',
    }), { message: 'stage10_test_restore_not_confirmed' });
    assert.throws(() => applyTestPolicyRestore({
      slot, expectedCurrentSha256: 'a'.repeat(64), confirmation: CONFIRMATION,
    }), { message: 'stage10_test_policy_changed_since_preview' });
    assert.equal(previewTestPolicyRestore(slot).matchesBackup, false);
    assert.equal(existsSync(testPolicyPaths(slot).audit), false);
  } finally { cleanup(slot); }
});

test('stage 10 task 2: only test policy is restored; earlier audit lines survive', async () => {
  const slot = newSlot();
  try {
    prepareDemoTestPolicy(slot);
    const { audit } = testPolicyPaths(slot);
    appendFileSync(audit, JSON.stringify({ event: 'preexisting_audit' }) + '\n');
    const before = previewTestPolicyRestore(slot);
    const result = applyTestPolicyRestore({
      slot, expectedCurrentSha256: before.currentSha256, confirmation: CONFIRMATION,
    });
    assert.equal(result.restored, true);
    assert.equal(result.matchesBackup, true);
    assert.equal(result.currentSha256, before.backupSha256);
    const auditLines = readFileSync(audit, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(auditLines.map(x => x.event),
      ['preexisting_audit', 'restore_planned', 'restore_applied']);
    assert.deepEqual(await checkRestoredTestPolicy(slot), {
      ownerAllowed: true,
      otherDenied: true,
      unregisteredDenied: true,
      unusualRequiresStepUp: true,
    });
    const second = applyTestPolicyRestore({
      slot, expectedCurrentSha256: result.currentSha256, confirmation: CONFIRMATION,
    });
    assert.equal(second.restored, false);
    assert.equal(readFileSync(audit, 'utf8').trim().split('\n').length, 3);
  } finally { cleanup(slot); }
});

test('stage 10 task 2: target is restricted to ignored sandbox paths', () => {
  for (const slot of ['../src/decider', 'src/decider.mjs', '/tmp/policy', '.env', 'test-other']) {
    assert.throws(() => testPolicyPaths(slot), { message: 'stage10_test_slot_not_allowed' });
  }
});
