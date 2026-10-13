import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runStage10SelfChecks, readTupleProofs } from '../src/stage10-self-check.mjs';

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
  const recovered = outcomes.find(row => row.attackId === 'stage10_local_restore_tuple_match');
  const measured = /id=([a-f0-9-]{36}); owner=([a-f0-9-]{36}); sha256=([a-f0-9]{64})/u;
  assert.deepEqual(recovered.expected.match(measured)?.slice(1), recovered.observed.match(measured)?.slice(1));
  assert.ok(recovered.expected.match(measured));
});

test('tuple evidence rejects missing, duplicate, owner/hash/response mismatch or invalid records', () => {
  const backup = { id: '123e4567-e89b-42d3-a456-426614174002',
    ownerId: '123e4567-e89b-42d3-a456-426614174001', contentSha256: 'a'.repeat(64) };
  const pair = ['tampered', 'deleted'].map(scenario => ({ scenario, scope: 'local_synthetic',
    backup: { ...backup }, restored: { ...backup }, response: { ...backup } }));
  const encode = values => values.map(row => '# STAGE10_TUPLE_PROOF ' + JSON.stringify(row)).join('\n');
  assert.equal(readTupleProofs(encode(pair)).length, 2);
  assert.equal(readTupleProofs(''), null);
  assert.equal(readTupleProofs(encode([pair[0]])), null);
  assert.equal(readTupleProofs(encode([pair[0], pair[0]])), null);
  for (const [record, field, bad] of [
    ['restored', 'ownerId', '123e4567-e89b-42d3-a456-426614174003'],
    ['restored', 'contentSha256', 'b'.repeat(64)],
    ['response', 'id', '123e4567-e89b-42d3-a456-426614174004'],
    ['backup', 'contentSha256', 'invalid'],
  ]) {
    const corrupted = structuredClone(pair); corrupted[0][record][field] = bad;
    assert.equal(readTupleProofs(encode(corrupted)), null);
  }
});
