import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { changedFilesForCommit } from '../scripts/bundle-commit-files.mjs';

test('submission bundle detects real changed files for root, simple and merge commits', () => {
  const directory = mkdtempSync(join(tmpdir(), 'stage10-bundle-checkpoint-'));
  const git = (...args) => execFileSync('git', ['-C', directory, ...args], {
    encoding: 'utf8', timeout: 8000, windowsHide: true,
  }).trim();
  try {
    git('init', '--quiet', '--initial-branch=main');
    git('config', 'user.name', 'Stage 10 Test');
    git('config', 'user.email', 'stage10-test@example.invalid');
    writeFileSync(join(directory, 'base.txt'), 'base\n');
    git('add', '.');
    git('commit', '--quiet', '-m', 'root');
    const rootCommit = git('rev-parse', 'HEAD');
    assert.deepEqual(changedFilesForCommit(git, rootCommit), ['base.txt']);

    git('switch', '--quiet', '-c', 'feature');
    writeFileSync(join(directory, 'feature.txt'), 'new feature\n');
    git('add', '.');
    git('commit', '--quiet', '-m', 'feature work');
    const featureCommit = git('rev-parse', 'HEAD');
    assert.deepEqual(changedFilesForCommit(git, featureCommit), ['feature.txt']);

    git('switch', '--quiet', 'main');
    writeFileSync(join(directory, 'main.txt'), 'unrelated main work\n');
    git('add', '.');
    git('commit', '--quiet', '-m', 'main work');
    git('merge', '--quiet', '--no-ff', '-m', 'Merge feature', 'feature');
    const mergeCommit = git('rev-parse', 'HEAD');
    // The merged feature is real work relative to the first parent, even
    // though plain git diff-tree -r <merge> reports an empty list.
    assert.deepEqual(changedFilesForCommit(git, mergeCommit), ['feature.txt']);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
