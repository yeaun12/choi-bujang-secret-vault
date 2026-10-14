import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

test('stage12 bundle subprocess surface is exactly two read-only Git calls', () => {
  const code = readFileSync(new URL('../scripts/bundle.mjs', import.meta.url), 'utf8');
  const entry = readFileSync(new URL('../scripts/bundle-entry.mjs', import.meta.url), 'utf8');
  const commands = [...code.matchAll(/\bgit\('([^']+)'/gu)].map(x => x[1]);
  assert.deepEqual(commands, ['rev-parse', 'show']);
  assert.match(code, /execFileSync\('git', args,/u);
  assert.match(code, /git\('rev-parse', 'HEAD'\)/u);
  assert.match(code, /git\('show', '--first-parent', '--format=', '--name-only', 'HEAD'\)/u);
  assert.equal((code.match(/execFileSync\(/gu) || []).length, 1);
  assert.doesNotMatch(code, /pathToFileURL|git\('config'|git\('remote'|git\('status'|\['-C'/u);
  assert.doesNotMatch(entry, /readFileSync\(new URL|writeFileSync\(new URL/u);
});

test('read-only git show yields first-parent changed file names for a merge', () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage12-merge-read-'));
  const git = (...args) => execFileSync('git', args, {cwd:dir, encoding:'utf8'}).trim();
  try {
    git('init', '-q');
    git('config', 'user.email', 'tester@example.invalid');
    git('config', 'user.name', 'test');
    writeFileSync(join(dir, 'base.txt'), 'base');
    git('add', '.'); git('commit', '-qm', 'base');
    git('branch', 'feature');
    writeFileSync(join(dir, 'main.txt'), 'main');
    git('add', '.'); git('commit', '-qm', 'main');
    const main = git('rev-parse', 'HEAD');
    git('switch', '-q', 'feature');
    writeFileSync(join(dir, 'feature.txt'), 'feature');
    git('add', '.'); git('commit', '-qm', 'feature');
    git('switch', '--detach', '-q', main);
    git('merge', '--no-ff', '-qm', 'merge feature', 'feature');
    assert.deepEqual(git('show', '--first-parent', '--format=', '--name-only', 'HEAD')
      .split(/\r?\n/u).filter(Boolean).sort(), ['feature.txt']);
  } finally {
    rmSync(dir, {recursive:true,force:true});
  }
});
