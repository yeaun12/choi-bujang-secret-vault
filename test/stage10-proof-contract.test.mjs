import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = path => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

test('current Stage 10 README points to an unambiguous live evidence contract', () => {
  const readme = read('README.md');
  const proof = read('docs/STAGE10_LIVE_PROOF_CONTRACT.md');
  assert.match(readme, /docs\/STAGE10_LIVE_PROOF_CONTRACT\.md/u);
  assert.match(readme, /수정 이전 방식\(과거 기록\)/u,
    'Old in-process GET descriptions must be clearly historical');
  for (const field of [
    'backup.creationAuditVerified', 'backup.creationAuditRereadBeforeRestore',
    'backup.rereadBeforeWrite', 'match.all', 'retestVerified',
    'retest.complete', 'retest.normal[]', 'retest.forbidden[]',
    'postRestoreRetest', 'retest.notRun',
  ]) assert.ok(proof.includes(field), 'Contract omits the evidence field ' + field);
  assert.match(proof, /HTTP 503/u);
  assert.match(proof, /UNV_AMBIGUOUS/u);
  assert.match(proof, /local_synthetic/u);
});

test('live proof description matches deployed restore response and outbound requests', () => {
  const restore = read('api/restore.js');
  const retest = read('src/stage10-postrestore-retest.mjs');
  assert.match(restore, /const restoredEvidence = \{/u);
  assert.match(restore, /restored: true,/u);
  assert.match(restore, /retestVerified: retest\.passed/u);
  assert.match(restore, /error: 'retest_evidence_unavailable'/u);
  assert.match(restore, /retestVerified: false/u);
  assert.match(restore, /postRestoreRetest: \{/u);
  assert.match(restore, /creationAuditRereadBeforeRestore: true/u);
  assert.match(restore, /retest\.passed \? 200 : 503/u);
  assert.doesNotMatch(restore, /getNoteItem\(/u,
    'Restore must not silently substitute in-process GET for HTTP');
  assert.match(retest, /fetchImpl\(url, \{/u);
  assert.match(retest, /status, result: passed \? 'passed' : 'failed'/u);
  assert.match(retest, /reason: 'not_run_no_verified_a_note'/u);
});
