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
  assert.deepEqual(imports, ['node:child_process', 'node:fs', 'node:path', '../src/decider.mjs']);
  assert.doesNotMatch(source, /import\(|require\(|stage10-self-check|attack-check|bundle-entry|bundle\.mjs/u);
  assert.doesNotMatch(source, /node:os|node:util|node:net|node:tls|node:http|node:https/u);
});
test('isolation is GET-only, has no credentials, and preserves unexecuted checks', () => {
  assert.match(source, /method: 'GET'/u);
  assert.doesNotMatch(source, /method: 'POST'|method: 'PUT'|method: 'DELETE'/u);
  assert.doesNotMatch(source, /Authorization:|Bearer [A-Za-z0-9._-]{12,}|https:\/\/.*@/u);
  assert.match(source, /observed: 'not_run'/u);
  assert.match(source, /official 41-case assault has not been independently verified/u);
  assert.match(source, /new URL\(path, app\)\.href/u);
});
test('only permitted Git reads are used; no git config, status, -C, or extra processes', () => {
  assert.match(source, /readGit\('rev-parse', 'HEAD'\)/u);
  assert.match(source, /readGit\('show', '--first-parent', '--format=', '--name-only', 'HEAD'\)/u);
  assert.doesNotMatch(source, /readGit\('(?:status|diff|config|remote|rev-list)'|'-C'/u);
  assert.equal((source.match(/execFileSync\(/gu) || []).length, 1);
});
test('fresh checkout requires only committed config, not private ignored bundle notes', () => {
  assert.match(source, /aleph\.config\.json/u);
  assert.doesNotMatch(source, /bundle-notes\.json|\.env|localStorage|sessionStorage/u);
  assert.match(source, /artifacts/u);
  assert.match(source, /submission\.json/u);
});
