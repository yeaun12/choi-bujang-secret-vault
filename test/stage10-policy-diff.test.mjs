import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SAFE_POLICY_PROVENANCE, readVerifiedSafePolicy, validatePolicySnapshot,
  comparePolicyText, readTestPolicy,
} from '../scripts/stage10-policy-diff.mjs';

test('stage 10 task 1: passed safe blob is intact and only the approved restore route was added', () => {
  const safe = readVerifiedSafePolicy();
  const current = readTestPolicy();
  assert.equal(SAFE_POLICY_PROVENANCE.blob.length, 40);

  // The safe policy from stages 8 and 9 must remain byte-for-byte identical
  // except for this precise, approved stage 10 POST recovery route insertion.
  // Any extra policy drift (including changes to earlier allow/deny rules)
  // must fail this test rather than being silently accepted.
  const approvedAddition = [
    "  // Stage 10 exact recovery route only. The server separately authenticates",
    "  // signed judge B and validates backup owner, note ID and SHA-256.",
    "  if (path === '/api/restore' && method === 'POST' &&",
    "      route === 'POST /api/restore') {",
    "    return { zone: 'restore', resourceId: 'restore:one_note' };",
    "  }",
    "",
  ].join('\n');
  assert.equal(current.split(approvedAddition).length, 2,
    'The exact approved recovery rule must occur once.');
  assert.equal(current.replace(approvedAddition, ''), safe,
    'Unexpected change to the stage 8/9 verified access policy.');

  const result = comparePolicyText(safe, current);
  assert.equal(result.matchesBackup, false);
  assert.equal(result.addedLines, 6);
  assert.equal(result.removedLines, 0);
});

test('stage 10 task 1: any corrupted or missing backup fails closed', () => {
  const original = SAFE_POLICY_PROVENANCE.blob;
  for (const faulty of [
    { stage8Blob: 'bad', stage9Blob: original, actualBlob: original },
    { stage8Blob: original, stage9Blob: 'bad', actualBlob: original },
    { stage8Blob: original, stage9Blob: original, actualBlob: 'bad' },
  ]) {
    assert.throws(() => validatePolicySnapshot(faulty),
      { message: 'stage10_safe_policy_backup_verification_failed' });
  }
});

test('stage 10 task 1: test policy drift displays only changed line metadata', () => {
  const safe = "const deviceRegistered = true;\nreturn 'deny';\n";
  const altered = "const deviceRegistered = false;\nreturn 'deny';\n";
  const result = comparePolicyText(safe, altered);
  assert.equal(result.matchesBackup, false);
  assert.equal(result.addedLines, 1);
  assert.equal(result.removedLines, 1);
  assert.ok(result.changedLines.some(x => x.area === 'device'));
  assert.equal(JSON.stringify(result).includes('deviceRegistered'), false);
});

test('stage 10 task 1: no arbitrary secret file paths or network URLs', () => {
  for (const candidate of ['../.env', '.env', 'api/auth/index.js', '/tmp/secret.mjs',
    'https://example.com/script.mjs', 'test/stage10/../secret.mjs']) {
    assert.throws(() => readTestPolicy(candidate),
      { message: 'stage10_unapproved_test_policy_path' });
  }
});
