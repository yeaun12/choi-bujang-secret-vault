// Stage 10 task 2: restore ONLY an isolated, ignored local test policy.
// Safe policy: independently verified Git blobs of officially passed stages 8/9.
// No production-policy writes, Supabase writes, changes to other services, or audit deletion.
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync,
  renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  SAFE_POLICY_PROVENANCE, comparePolicyText, readVerifiedSafePolicy,
} from './stage10-policy-diff.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SANDBOX = join(ROOT, '.stage10-sandbox');
export const DEFAULT_SLOT = 'policy-under-test';
export const CONFIRMATION = 'TEST_ONLY';
const SHA256 = /^[a-f0-9]{64}$/u;
const DEMO_NEEDLE = 'const registered = request?.deviceRegistered === true;';

function assertSlot(slot) {
  if (slot !== DEFAULT_SLOT && !/^test-[a-f0-9]{8}$/u.test(slot)) {
    throw new Error('stage10_test_slot_not_allowed');
  }
}

export function testPolicyPaths(slot = DEFAULT_SLOT) {
  assertSlot(slot);
  if (existsSync(SANDBOX)) {
    const info = lstatSync(SANDBOX);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error('stage10_unsafe_sandbox');
    }
  }
  return {
    candidate: join(SANDBOX, slot + '.mjs'),
    audit: join(SANDBOX, slot + '.audit.jsonl'),
    relative: '.stage10-sandbox/' + slot + '.mjs',
  };
}

function regularFile(path) {
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 256000) {
    throw new Error('stage10_unsafe_test_file');
  }
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function readCandidate(path) {
  regularFile(path);
  return readFileSync(path, 'utf8');
}

function assertUntracked(relative) {
  const files = execFileSync('git', ['ls-files', '--', relative], {
    cwd: ROOT, encoding: 'utf8', timeout: 5000, windowsHide: true,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  }).trim();
  if (files) throw new Error('stage10_tracked_test_file');
}

export function prepareDemoTestPolicy(slot = DEFAULT_SLOT) {
  // Explicit opt-in synthetic drift, never a deployed or live policy change.
  const safe = readVerifiedSafePolicy();
  const paths = testPolicyPaths(slot);
  if (existsSync(paths.candidate)) throw new Error('stage10_test_file_exists');
  if (safe.split(DEMO_NEEDLE).length !== 2) {
    throw new Error('stage10_demo_policy_template_changed');
  }
  mkdirSync(SANDBOX, { recursive: true });
  testPolicyPaths(slot); // recheck that no symlink appeared
  assertUntracked(paths.relative);
  const modified = safe.replace(DEMO_NEEDLE,
    'const registered = request?.deviceRegistered === false;');
  writeFileSync(paths.candidate, modified, { flag: 'wx', mode: 0o600 });
  return { file: paths.relative, synthetic: true };
}

export function previewTestPolicyRestore(slot = DEFAULT_SLOT) {
  // Fail closed if any passed Git snapshot is missing or modified.
  const safe = readVerifiedSafePolicy();
  const paths = testPolicyPaths(slot);
  const current = readCandidate(paths.candidate);
  assertUntracked(paths.relative);
  const diff = comparePolicyText(safe, current);
  return {
    file: paths.relative,
    backupCommit: SAFE_POLICY_PROVENANCE.stage9Commit,
    backupBlob: SAFE_POLICY_PROVENANCE.blob,
    backupSha256: diff.backupSha256,
    currentSha256: diff.testSha256,
    matchesBackup: diff.matchesBackup,
    addedLines: diff.addedLines,
    removedLines: diff.removedLines,
    changedLines: diff.changedLines,
    affects: [paths.relative],
    changesProductionPolicy: false,
    changesDatabase: false,
  };
}

export function applyTestPolicyRestore({
  slot = DEFAULT_SLOT, expectedCurrentSha256, confirmation,
} = {}) {
  if (confirmation !== CONFIRMATION
      || typeof expectedCurrentSha256 !== 'string'
      || !SHA256.test(expectedCurrentSha256)) {
    throw new Error('stage10_test_restore_not_confirmed');
  }
  const plan = previewTestPolicyRestore(slot);
  if (plan.currentSha256 !== expectedCurrentSha256) {
    throw new Error('stage10_test_policy_changed_since_preview');
  }
  if (plan.matchesBackup) {
    return { restored: false, reason: 'already_matches_safe_policy', ...plan };
  }
  // Reverify snapshot and the source test file immediately before the write.
  const safe = readVerifiedSafePolicy();
  const paths = testPolicyPaths(slot);
  if (sha256(readCandidate(paths.candidate)) !== plan.currentSha256) {
    throw new Error('stage10_test_policy_changed_since_preview');
  }
  if (existsSync(paths.audit)) regularFile(paths.audit);
  const note = event => JSON.stringify({
    event,
    policy: 'stage10_test_only',
    safeBlob: SAFE_POLICY_PROVENANCE.blob,
    priorSha256: plan.currentSha256,
    restoredSha256: plan.backupSha256,
  }) + '\n';
  // Audit is append-only and contains no event bodies, tokens or identities.
  appendFileSync(paths.audit, note('restore_planned'), { flag: 'a', mode: 0o600 });
  const temp = join(SANDBOX, '.restore-' + randomBytes(8).toString('hex') + '.tmp');
  try {
    writeFileSync(temp, safe, { flag: 'wx', mode: 0o600 });
    if (sha256(readCandidate(paths.candidate)) !== plan.currentSha256) {
      throw new Error('stage10_test_policy_changed_since_preview');
    }
    renameSync(temp, paths.candidate);
  } finally {
    if (existsSync(temp)) rmSync(temp, { force: true });
  }
  if (sha256(readCandidate(paths.candidate)) !== plan.backupSha256) {
    throw new Error('stage10_test_restore_verification_failed');
  }
  appendFileSync(paths.audit, note('restore_applied'), { flag: 'a', mode: 0o600 });
  return { restored: true, ...previewTestPolicyRestore(slot) };
}

export async function checkRestoredTestPolicy(slot = DEFAULT_SLOT) {
  const plan = previewTestPolicyRestore(slot);
  if (!plan.matchesBackup) throw new Error('stage10_test_policy_not_restored');
  const file = testPolicyPaths(slot).candidate;
  const { decide } = await import(pathToFileURL(file).href + '?sha=' + plan.currentSha256);
  const { fixtureRequests } = await import('./fixture-7.mjs');
  const { normal, suspicious } = fixtureRequests();
  const A = await decide(normal);
  const B = await decide({ ...normal, requestId: 'stage10-b', subjectId: 'other_learner_fixture' });
  const unregistered = await decide({ ...normal, requestId: 'stage10-unregistered',
    deviceRegistered: false });
  const risk = await decide(suspicious);
  const results = {
    ownerAllowed: A.decision === 'allow',
    otherDenied: B.decision === 'deny',
    unregisteredDenied: unregistered.decision === 'deny',
    unusualRequiresStepUp: risk.decision === 'step_up',
  };
  if (Object.values(results).some(value => !value)) {
    throw new Error('stage10_restored_policy_fixture_failed');
  }
  return results;
}

const isCli = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 1 && args[0] === '--prepare-demo') {
      const created = prepareDemoTestPolicy();
      process.stdout.write('격리된 시험 정책 생성: ' + created.file + '\n'
        + '운영 정책·DB 변경 없음\n');
    } else if (args.length === 1 && (args[0] === '--preview' || args[0] === '--verify')) {
      const plan = previewTestPolicyRestore();
      process.stdout.write(
        '검증된 백업: ' + plan.backupCommit.slice(0, 12) + '\n'
        + '변경 대상: ' + plan.file + '\n'
        + '변경 범위: +' + plan.addedLines + ' / -' + plan.removedLines + ' lines\n'
        + '현재 파일 SHA256: ' + plan.currentSha256 + '\n'
      );
      for (const item of plan.changedLines.slice(0, 80)) {
        process.stdout.write(item.change + ' '
          + (item.backupLine ? 'backup:L' + item.backupLine : 'test:L' + item.testLine)
          + ' area=' + item.area + '\n');
      }
      process.stdout.write(plan.matchesBackup ? '정책 시험 파일이 안전본과 일치\n' :
        '승인 전에는 어떤 파일도 복원하지 않습니다.\n');
      if (args[0] === '--verify') {
        if (!plan.matchesBackup) throw new Error('stage10_test_policy_not_restored');
        const result = await checkRestoredTestPolicy();
        process.stdout.write('가상 A 정상: ' + (result.ownerAllowed ? 'allow' : 'fail') + '\n'
          + '가상 B A자료 접근: ' + (result.otherDenied ? 'deny' : 'fail') + '\n'
          + '미등록 기기: ' + (result.unregisteredDenied ? 'deny' : 'fail') + '\n'
          + '복합 이상 접속: ' + (result.unusualRequiresStepUp ? 'step_up' : 'fail') + '\n');
      } else if (!plan.matchesBackup) {
        process.stdout.write('명시적 승인 시 실행할 명령:\n'
          + 'node scripts/stage10-policy-restore.mjs --apply '
          + plan.currentSha256 + ' --confirm TEST_ONLY\n');
      }
    } else if (args.length === 4 && args[0] === '--apply'
        && args[2] === '--confirm') {
      const result = applyTestPolicyRestore({
        expectedCurrentSha256: args[1], confirmation: args[3],
      });
      process.stdout.write(result.restored ? '격리 시험 정책 복원 확인: PASS\n' :
        '시험 정책은 이미 안전본과 일치: 변경 없음\n');
      process.stdout.write('대상: ' + result.file + '\n'
        + '운영 정책·DB·다른 서비스 규칙 변경 없음\n');
    } else {
      throw new Error('stage10_invalid_arguments');
    }
  } catch {
    // Do not expose source policies or raw exception content.
    process.stderr.write('10단계 제작2 중단: 백업·시험 정책·승인 또는 무결성 검증 실패\n');
    process.exitCode = 1;
  }
}
