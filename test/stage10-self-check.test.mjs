import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runStage10SelfChecks } from '../src/stage10-self-check.mjs';

test('fresh recovery self-check runs the HTTP flow and isolated policy without changing deployed policy', async () => {
  const before = readFileSync(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  const outcomes = await runStage10SelfChecks();
  assert.equal(outcomes.length, 5);
  assert.equal(new Set(outcomes.map(row => row.attackId)).size, 5);
  assert.ok(outcomes.every(row => row.observed.startsWith('PASS:')));
  assert.ok(outcomes.every(row => Object.keys(row).sort().join(',') === 'attackId,expected,observed'));
  assert.ok(outcomes.every(row => row.expected.length <= 300 && row.observed.length <= 300));
  assert.ok(outcomes.filter(row => row.attackId.startsWith('stage10_local_'))
    .every(row => row.observed.includes('not production/judge evidence')));
  assert.equal(readFileSync(new URL('../src/decider.mjs', import.meta.url), 'utf8'), before);
  assert.equal(JSON.stringify(outcomes).includes('Synthetic original B fixture'), false);
  assert.doesNotMatch(JSON.stringify(outcomes), /Bearer\s|-----BEGIN/u);
});
