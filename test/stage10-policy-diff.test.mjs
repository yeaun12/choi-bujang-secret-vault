import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SAFE_POLICY_PROVENANCE, readVerifiedSafePolicy, validatePolicySnapshot,
  comparePolicyText, readTestPolicy,
} from '../scripts/stage10-policy-diff.mjs';

test('stage 10 task 1: verified stage 8 and 9 policy blobs agree', () => {
  const safe = readVerifiedSafePolicy();
  const current = readTestPolicy();
  const result = comparePolicyText(safe, current);
  assert.equal(SAFE_POLICY_PROVENANCE.blob.length, 40);
  assert.equal(result.matchesBackup, true);
  assert.equal(result.addedLines, 0);
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
