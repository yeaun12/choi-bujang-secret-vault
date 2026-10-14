import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../scripts/stage12-isolated-bundle.mjs', import.meta.url), 'utf8');
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('stage 12 bundle points to the isolated entry, not the legacy bundle', () => {
  assert.equal(pkg.scripts.bundle, 'node scripts/stage12-isolated-bundle.mjs');
  assert.equal(pkg.scripts['bundle:legacy'], 'node scripts/bundle-entry.mjs');
});
test('stage 12 entry uses only allowed modules and does not load legacy checkers', () => {
  const imports = [...source.matchAll(/^import .* from ['"]([^'"]+)['"];?$/gmu)].map(x => x[1]);
  assert.deepEqual(imports, ['node:fs', 'node:path', '../src/decider.mjs']);
  assert.doesNotMatch(source, /import\(|require\(|stage10-self-check|attack-check|bundle-entry|from ['"][^'"]*\/bundle\.mjs/u);
  assert.doesNotMatch(source, /node:os|node:util|node:net|node:tls|node:http|node:https/u);
});
test('unverifiable API GETs are not executed or claimed as observed', () => {
  assert.doesNotMatch(source, /\bfetch\(|\bpublicGet\b|\bobservedGet\b|method: 'POST'|method: 'PUT'|method: 'DELETE'/u);
  assert.doesNotMatch(source, /Authorization:|Bearer [A-Za-z0-9._-]{12,}|https:\/\/.*@/u);
  assert.equal((source.match(/^  notRun\('/gmu) || []).length, 13);
  for (const id of [
    'static_note_file_removed',
    'anonymous_note_list_denied',
    'anonymous_instructor_notice_read_denied',
    'anonymous_war_room_read_denied',
  ]) {
    assert(source.includes("  notRun('" + id + "'"));
  }
  assert.match(source, /observed: 'not_run'/u);
  assert.match(source, /official 41-case assault has not been independently verified/u);
});
test('sandbox bundle launches zero subprocesses and reads checkout identity from fs', () => {
  assert.match(source, /function currentCommitFromCheckout\(/u);
  assert.match(source, /join\(gitDir, 'HEAD'\)/u);
  assert.match(source, /packed-refs/u);
  assert.doesNotMatch(source, /node:child_process|execFileSync|spawn|readGit\(/u);
  assert.deepEqual([...source.matchAll(/'([^']+\.mjs)'/gu)].map(x => x[1])
    .filter(x => x.startsWith('scripts/') || x.startsWith('test/')), [
      'scripts/stage12-isolated-bundle.mjs', 'test/stage12-hermetic-bundle.test.mjs',
    ]);
});
test('fresh checkout requires only committed config, not private ignored bundle notes', () => {
  assert.match(source, /aleph\.config\.json/u);
  assert.doesNotMatch(source, /bundle-notes\.json|\.env|localStorage|sessionStorage/u);
  assert.match(source, /artifacts/u);
  assert.match(source, /submission\.json/u);
});
