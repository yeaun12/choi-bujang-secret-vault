// Stage 10 / task 1: read-only, fail-closed source-policy comparison.
// This verifies the exact policy Git blob that passed stages 8 and 9.
// It does not constitute a Supabase RLS or note-content backup.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(import.meta.dirname, '..');
export const SAFE_POLICY_PROVENANCE = Object.freeze({
  stage8Commit: '22ba9421e4690a6aec02d624d1848821278e8f6d',
  stage9Commit: 'a38a40a6ba03e34f2eaca337082c8bfefc084a6f',
  path: 'src/decider.mjs',
  blob: '3d8715d5aa11a548c72e7188028f7c2539af8ef8',
});

function git(args, input) {
  return execFileSync('git', args, {
    cwd: ROOT, input, encoding: 'utf8', timeout: 5000,
    maxBuffer: 1024 * 1024, windowsHide: true,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  }).trimEnd();
}

export function validatePolicySnapshot({ stage8Blob, stage9Blob, actualBlob }) {
  const expected = SAFE_POLICY_PROVENANCE.blob;
  if (![stage8Blob, stage9Blob, actualBlob].every(value => value === expected)) {
    throw new Error('stage10_safe_policy_backup_verification_failed');
  }
  return true;
}

export function readVerifiedSafePolicy() {
  const { stage8Commit, stage9Commit, path } = SAFE_POLICY_PROVENANCE;
  const blobAt8 = git(['rev-parse', stage8Commit + ':' + path]).trim();
  const blobAt9 = git(['rev-parse', stage9Commit + ':' + path]).trim();
  const source = git(['show', stage9Commit + ':' + path]) + '\n';
  const actualBlob = git(['hash-object', '--stdin'], source).trim();
  validatePolicySnapshot({ stage8Blob: blobAt8, stage9Blob: blobAt9, actualBlob });
  return source;
}

// Compare lines without executing either policy or printing untrusted source text.
const labelFor = line => {
  if (/device_registered|deviceRegistered/u.test(line)) return 'device';
  if (/step_up|stepUp|risk_signal/u.test(line)) return 'step_up';
  if (/resource_scope|NOTE_|NOTICE_|resource|owner/u.test(line)) return 'resource_scope';
  if (/allow|deny|method|path|route/u.test(line)) return 'decision_or_route';
  return 'other';
};

export function comparePolicyText(safeText, testText) {
  if (typeof safeText !== 'string' || typeof testText !== 'string'
      || safeText.length > 256000 || testText.length > 256000) {
    throw new Error('stage10_policy_comparison_invalid_input');
  }
  const normalize = text => text.replace(/\r\n/gu, '\n').replace(/\n$/u, '').split('\n');
  const safe = normalize(safeText);
  const test = normalize(testText);
  if (safe.length > 2000 || test.length > 2000) {
    throw new Error('stage10_policy_comparison_invalid_input');
  }
  const cells = Array.from({ length: safe.length + 1 },
    () => new Uint16Array(test.length + 1));
  for (let i = safe.length - 1; i >= 0; i--) {
    for (let j = test.length - 1; j >= 0; j--) {
      cells[i][j] = safe[i] === test[j]
        ? 1 + cells[i + 1][j + 1]
        : Math.max(cells[i + 1][j], cells[i][j + 1]);
    }
  }
  const changes = [];
  let i = 0, j = 0;
  while (i < safe.length || j < test.length) {
    if (i < safe.length && j < test.length && safe[i] === test[j]) {
      i++; j++;
    } else if (j < test.length && (i === safe.length || cells[i][j + 1] >= cells[i + 1][j])) {
      changes.push({ change: 'added_to_test', testLine: j + 1, area: labelFor(test[j]) });
      j++;
    } else {
      changes.push({ change: 'removed_from_test', backupLine: i + 1, area: labelFor(safe[i]) });
      i++;
    }
  }
  return {
    matchesBackup: changes.length === 0,
    backupSha256: createHash('sha256').update(safeText).digest('hex'),
    testSha256: createHash('sha256').update(testText).digest('hex'),
    addedLines: changes.filter(x => x.change === 'added_to_test').length,
    removedLines: changes.filter(x => x.change === 'removed_from_test').length,
    changedLines: changes,
  };
}

export function readTestPolicy(candidate = 'src/decider.mjs') {
  // No arbitrary system files, secrets or network-provided URLs can be read.
  if (candidate !== 'src/decider.mjs'
      && !/^test\/stage10\/[a-z0-9_.-]+\.mjs$/u.test(candidate)) {
    throw new Error('stage10_unapproved_test_policy_path');
  }
  return readFileSync(join(ROOT, candidate), 'utf8');
}

const isCli = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && !(args.length === 2 && args[0] === '--test-policy')) {
      throw new Error('stage10_invalid_arguments');
    }
    const candidatePath = args.length === 0 ? 'src/decider.mjs' : args[1];
    // Verify the baseline BEFORE reading or comparing the test policy.
    const safe = readVerifiedSafePolicy();
    const test = readTestPolicy(candidatePath);
    const result = comparePolicyText(safe, test);
    process.stdout.write(
      '안전 정책 기준본 검증: PASS\n'
      + '8단계 통과 버전: ' + SAFE_POLICY_PROVENANCE.stage8Commit.slice(0, 12) + '\n'
      + '9단계 통과 버전: ' + SAFE_POLICY_PROVENANCE.stage9Commit.slice(0, 12) + '\n'
      + '정책 Git blob: ' + SAFE_POLICY_PROVENANCE.blob + '\n'
      + '시험 정책 파일: ' + candidatePath + '\n'
      + '차이: +' + result.addedLines + ' / -' + result.removedLines + ' lines\n'
      + (result.matchesBackup ? '정책 파일 차이 없음\n' : '')
    );
    for (const entry of result.changedLines.slice(0, 100)) {
      process.stdout.write(
        entry.change + ' ' + (entry.backupLine ? 'backup:L' + entry.backupLine : 'test:L' + entry.testLine)
        + ' area=' + entry.area + '\n'
      );
    }
    if (result.changedLines.length > 100) {
      process.stdout.write('추가 변경 줄: ' + (result.changedLines.length - 100) + '\n');
    }
    process.stdout.write('실제 정책·DB 변경: 없음\n');
  } catch {
    // Never print raw Git errors, policy text, tokens or external file contents.
    process.stderr.write('10단계 제작1 중단: 안전 사본 확인/시험 정책 읽기 실패\n');
    process.exitCode = 1;
  }
}
