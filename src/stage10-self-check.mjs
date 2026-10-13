// Reproducible self-check evidence. Never label local fixtures as live judge tests.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes, createHash } from 'node:crypto';
import { appendFileSync, readFileSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { readVerifiedSafePolicy, SAFE_POLICY_PROVENANCE } from '../scripts/stage10-policy-diff.mjs';
import {
  prepareDemoTestPolicy, previewTestPolicyRestore, applyTestPolicyRestore,
  checkRestoredTestPolicy, testPolicyPaths,
} from '../scripts/stage10-policy-restore.mjs';

const root = resolve(import.meta.dirname, '..');
const execute = promisify(execFile);
const fingerprint = () => createHash('sha256')
  .update(readFileSync(join(root, 'src/decider.mjs'))).digest('hex');

export function readTupleProofs(output) {
  const tuples = [];
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  for (const line of output.split('\n')) {
    const match = /^\s*# STAGE10_TUPLE_PROOF (.+)$/u.exec(line);
    if (!match) continue;
    let value;
    try { value = JSON.parse(match[1]); } catch { return null; }
    if (value?.scope !== 'local_synthetic' || !['tampered', 'deleted'].includes(value.scenario)) return null;
    const records = [value.backup, value.restored, value.response];
    if (!records.every(row => row && uuid.test(row.id ?? '') && uuid.test(row.ownerId ?? '')
        && /^[a-f0-9]{64}$/u.test(row.contentSha256 ?? '')
        && Object.keys(row).sort().join(',') === 'contentSha256,id,ownerId')) return null;
    if (!['id', 'ownerId', 'contentSha256'].every(key =>
      value.backup[key] === value.restored[key] && value.backup[key] === value.response[key])) return null;
    tuples.push(value);
  }
  if (tuples.length !== 2 || new Set(tuples.map(row => row.scenario)).size !== 2) return null;
  return tuples;
}

export async function runStage10SelfChecks() {
  const checks = [];
  let policyVerified = false;
  try { readVerifiedSafePolicy(); policyVerified = true; } catch { /* fail closed */ }
  checks.push({
    attackId: 'stage10_safe_policy_backup_verified',
    expected: 'Independently read and verify the Git policy backup from passed stages 8 and 9.',
    observed: policyVerified
      ? 'PASS: verified Git blob ' + SAFE_POLICY_PROVENANCE.blob + '; local policy evidence, not a live API check.'
      : 'FAILED: safe Git policy backup could not be verified; restoration not authorized.',
  });
  let policyRestored = false;
  const slot = 'test-' + randomBytes(4).toString('hex');
  const paths = testPolicyPaths(slot);
  let prepared = false;
  const sentinel = JSON.stringify({ event: 'prior_synthetic_audit' }) + '\n';
  try {
    if (!policyVerified) throw new Error('unverified');
    const before = fingerprint();
    prepareDemoTestPolicy(slot); prepared = true;
    appendFileSync(paths.audit, sentinel, { flag: 'wx', mode: 0o600 });
    const plan = previewTestPolicyRestore(slot);
    const restored = applyTestPolicyRestore({ slot, confirmation: 'TEST_ONLY',
      expectedCurrentSha256: plan.currentSha256 });
    const outcomes = await checkRestoredTestPolicy(slot);
    policyRestored = restored.restored && Object.values(outcomes).every(Boolean)
      && readFileSync(paths.audit, 'utf8').startsWith(sentinel) && fingerprint() === before;
  } catch { /* Report failure without raw source/error contents. */ }
  finally {
    if (prepared) { rmSync(paths.candidate, { force: true }); rmSync(paths.audit, { force: true }); }
  }
  checks.push({
    attackId: 'stage10_isolated_policy_restored',
    expected: 'Preview and restore only the isolated test policy, preserving deployed policy and prior audit.',
    observed: policyRestored
      ? 'PASS: local test policy restored; A allowed, B cross-owner denied; prior audit and deployed policy preserved.'
      : 'FAILED: isolated policy restoration or its local normal/forbidden checks did not pass.',
  });

  let output = '', suitePassed = false;
  try {
    const childEnv = { ...process.env };
    // This is a separate test-runner invocation, not a worker of a parent suite.
    delete childEnv.NODE_TEST_CONTEXT;
    const run = await execute(process.execPath, [
      '--experimental-test-module-mocks', '--test', '--test-reporter=tap',
      'test/stage10-api-flow.test.mjs',
    ], { cwd: root, env: childEnv, timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true });
    output = run.stdout;
    suitePassed = /^# tests 6\s*$/mu.test(output) && /^# fail 0\s*$/mu.test(output);
  } catch { /* Local execution failures are failed checks, not fabricated passes. */ }
  const passed = name => suitePassed && output.split('\n')
    .some(line => line.startsWith('ok ') && line.endsWith(' - ' + name));
  const full = passed('full API flow: signed creation, immutable backup, mutation, preview, exact restoration and retests');
  const missing = passed('missing or corrupt backup aborts without changing notes');
  const deleted = passed('deleted B note recreated from its original backup, retaining other notes and audit');
  const incomplete = passed('unexecuted A cross-owner retest makes the overall result incomplete');
  const proofs = readTupleProofs(output);
  const tamperedProof = proofs?.find(row => row.scenario === 'tampered');
  const tuple = row => 'id=' + row.id + '; owner=' + row.ownerId + '; sha256=' + row.contentSha256;
  const groups = [
    ['stage10_local_backup_readback', full && missing,
      'Re-read the stored synthetic B snapshot; missing/corrupt backups must abort before writes.',
      'Backup readback and missing/corrupt rejection verified.'],
    ['stage10_local_postrestore_retests', full && incomplete,
      'Execute normal and forbidden requests after local recovery; an unexecuted A check must keep overall passed=false.',
      'Normal 200/hash match; anonymous 401, query 400, cross-owner 404; missing A remains unexecuted.'],
  ];
  for (const [attackId, ok, expected, detail] of groups) {
    checks.push({ attackId, expected,
      observed: (ok ? 'PASS: ' + detail : 'FAILED: corresponding API integration assertions did not pass.')
        + ' Local HTTP with synthetic signed tokens and test storage; not production/judge evidence.' });
  }
  checks.splice(3, 0, {
    attackId: 'stage10_local_restore_tuple_match',
    expected: tamperedProof ? 'Local synthetic B backup: ' + tuple(tamperedProof.backup)
      : 'Local synthetic B recovery requires measured backup, restored row and response ID/owner/SHA-256.',
    observed: full && deleted && proofs
      ? 'PASS: restored ' + tuple(tamperedProof.restored)
        + '; backup/response match; delete checked; others/audit preserved. Local test storage; not production/judge evidence.'
      : 'FAILED: measured backup/restored/response tuple evidence missing or mismatched; not a verified recovery.',
  });
  return checks;
}
