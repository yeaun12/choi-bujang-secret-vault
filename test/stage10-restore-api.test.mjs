import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRestoreBody } from '../api/restore.js';
import {
  sha256, snapshotFromCreatedNote, previewOneJudgeBNote,
  restoreOneJudgeBNote, findSingleChangedJudgeBNote,
} from '../src/stage10-note-recovery.mjs';
import { runPostRestoreHttpRetests } from '../src/stage10-postrestore-retest.mjs';
import { noteScopeOwnerId } from '../src/resource-api-auth.mjs';

const B = { kind: 'judge', identity: 'b',
  runId: '123e4567-e89b-42d3-a456-426614174000',
  userId: '123e4567-e89b-42d3-a456-426614174001' };
const id = '123e4567-e89b-42d3-a456-426614174002';
const other = '123e4567-e89b-42d3-a456-426614174003';
const owner = noteScopeOwnerId(B);
const created_at = '2026-10-01T00:00:00.000Z';
const note = (noteId, content) => ({ id: noteId, owner_id: owner, title: 't', content, created_at });
const snap = n => ({ ...snapshotFromCreatedNote(B, n), captured_at: '2026-10-01T00:01:00.000Z' });

function memory(rows, backups) {
  const notes = new Map(rows.map(r => [r.id, { ...r }]));
  const saved = new Map(backups.map(b => [b.note_id, { ...b }]));
  const audits = [];
  return { notes, audits, repository: {
    async appendAudit(v) { audits.push(v); },
    async findBackup({ note_id }) { return saved.get(note_id) ?? null; },
    async listBackupNoteIds() { return [...saved.keys()]; },
    async findNoteById(x) { return notes.has(x) ? { ...notes.get(x) } : null; },
    async insertOwnedNote(v) { notes.set(v.id, { ...v }); return v; },
    async updateOwnedNote(v) { notes.set(v.id, { ...v }); return v; },
    async findFirstNoteIdByOwner() { return null; },
  } };
}

test('restore body: one note id, optional preview and expectations; ambiguity rejected', () => {
  assert.deepEqual(parseRestoreBody({ noteId: id }),
    { noteId: id, preview: false, expectedSha256: null, expectedOwnerId: null });
  assert.equal(parseRestoreBody({ id, reason: 'tampered' }).noteId, id);
  assert.equal(parseRestoreBody({ note_id: id, dryRun: true }).preview, true);
  assert.equal(parseRestoreBody(null).noteId, null);
  assert.equal(parseRestoreBody({ noteId: id, id: other }), null);
  assert.equal(parseRestoreBody([id]), null);
  assert.equal(parseRestoreBody({ noteId: id, contentSha256: 'xyz' }), null);
});

test('preview re-reads backup and lists changes without writing', async () => {
  const original = note(id, 'safe');
  const db = memory([{ ...original, content: 'tampered' }], [snap(original)]);
  const plan = await previewOneJudgeBNote({ identity: B, noteId: id, repository: db.repository });
  assert.equal(plan.status, 200);
  assert.deepEqual(plan.changedFields, ['content']);
  assert.equal(plan.backup.verified, true);
  assert.equal(plan.backup.contentSha256, sha256('safe'));
  assert.equal(db.notes.get(id).content, 'tampered');
});

test('preview fails closed when backup is missing', async () => {
  const db = memory([note(id, 'x')], []);
  const plan = await previewOneJudgeBNote({ identity: B, noteId: id, repository: db.repository });
  assert.equal(plan.status, 404);
});

test('tampered note restored alone; other note untouched; evidence matches backup', async () => {
  const a = note(id, 'safe'); const b = note(other, 'keep');
  const db = memory([{ ...a, content: 'tampered' }, { ...b, content: 'user edit' }],
    [snap(a)]);
  assert.equal(await findSingleChangedJudgeBNote({ identity: B, repository: db.repository }), id);
  const result = await restoreOneJudgeBNote({ identity: B, noteId: id, repository: db.repository });
  assert.equal(result.status, 200);
  assert.equal(result.mode, 'repaired');
  assert.deepEqual(result.changedFields, ['content']);
  assert.equal(result.backup.noteId, result.noteId);
  assert.equal(result.backup.ownerId, result.ownerId);
  assert.equal(result.backup.contentSha256, result.contentSha256);
  assert.equal(db.notes.get(other).content, 'user edit');
});

test('retest reports normal/forbidden kinds and keeps unexecuted checks as not run', async () => {
  const db = memory([], []);
  const statusFor = url => (url.includes('?') ? 400 : 401);
  const out = await runPostRestoreHttpRetests({
    identity: B, noteId: id, expectedSha256: sha256('safe'),
    authorization: 'Bearer a.b.c',
    requestUrl: 'https://choi-bujang-secret-vault-blush.vercel.app/api/restore',
    configuredAppUrl: 'https://choi-bujang-secret-vault-blush.vercel.app/',
    repository: db.repository,
    fetchImpl: async (url, init) => (init.headers.Authorization && !String(url).includes('?')
      ? Response.json({ id, body: 'safe' }) : new Response('', { status: statusFor(String(url)) })),
  });
  assert.equal(out.passed, true);
  assert.equal(out.complete, true);
  assert.deepEqual(out.skipped.map(x => x.check), ['foreign_denied']);
  assert.deepEqual(out.results.map(x => [x.check, x.kind, x.result]), [
    ['normal_read', 'normal', 'passed'],
    ['anonymous_denied', 'forbidden', 'passed'],
    ['query_rejected', 'forbidden', 'passed'],
  ]);
});
