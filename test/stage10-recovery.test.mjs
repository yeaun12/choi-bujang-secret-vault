import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isJudgeB, sha256, snapshotFromCreatedNote,
  backupCreatedJudgeBNote, backupBeforeJudgeBMutation,
  readVerifiedBackup, restoreOneJudgeBNote, sameStoredInstant,
} from '../src/stage10-note-recovery.mjs';
import { noteScopeOwnerId } from '../src/resource-api-auth.mjs';

const B = { kind: 'judge', identity: 'b',
  runId: '123e4567-e89b-42d3-a456-426614174000',
  userId: '123e4567-e89b-42d3-a456-426614174001' };
const A = { ...B, identity: 'a' };
const id = '123e4567-e89b-42d3-a456-426614174002';
const created_at = '2026-10-01T00:00:00.000Z';
const owner = noteScopeOwnerId(B);
const original = { id, owner_id: owner, title: 'fixture', content: 'safe note', created_at };
const snapshot = () => ({
  ...snapshotFromCreatedNote(B, original),
  captured_at: '2026-10-01T00:01:00.000Z',
});
function memory({ current = original, backup = null } = {}) {
  let row = current && { ...current };
  let saved = backup && { ...backup };
  const audits = [];
  const repository = {
    async insertBackup(s) {
      if (saved) throw new Error('duplicate_backup');
      saved = { ...s, captured_at: '2026-10-01T00:01:00.000Z' };
    },
    async appendAudit(v) { audits.push(v); },
    async findBackup() { return saved; },
    async findNoteById() { return row && { ...row }; },
    async insertOwnedNote(v) { if (row) return null; row = { ...v }; return row; },
    async updateOwnedNote(v) {
      if (!row || row.owner_id !== v.owner_id) return null;
      row = { ...v }; return row;
    },
  };
  return { repository, audits, get row() { return row; },
    get backup() { return saved; } };
}
test('judge-B only: capture original at creation and do not overwrite backup', async () => {
  assert.equal(isJudgeB(B), true);
  assert.equal(isJudgeB(A), false);
  assert.equal(isJudgeB({ ...B, kind: 'student' }), false);
  const db = memory();
  await backupCreatedJudgeBNote({ identity: B, note: original, repository: db.repository });
  assert.equal(db.backup.content_sha256, sha256(original.content));
  assert.deepEqual(db.audits.map(x => x.event_kind), ['backup_created']);
  await assert.rejects(backupCreatedJudgeBNote({
    identity: B, note: original, repository: db.repository,
  }), /duplicate_backup/u);
  assert.deepEqual(await backupCreatedJudgeBNote({
    identity: A, note: original, repository: db.repository,
  }), { skipped: true });
});
test('modified B note is repaired to exact ID, owner and content hash', async () => {
  const db = memory({ current: { ...original, title: 'altered', content: 'changed' },
    backup: snapshot() });
  const result = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: db.repository,
  });
  assert.equal(result.status, 200);
  assert.equal(result.mode, 'repaired');
  assert.deepEqual(db.row, original);
  assert.equal(result.contentSha256, sha256(original.content));
  assert.deepEqual(db.audits.map(x => x.event_kind),
    ['restore_requested', 'restore_verified']);
});
test('deleted B note is recreated once, keeping original ID', async () => {
  const db = memory({ current: null, backup: snapshot() });
  const result = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: db.repository,
  });
  assert.equal(result.mode, 'recreated');
  assert.deepEqual(db.row, original);
});
test('missing backup, bad hash, owner conflict and A request all fail closed', async () => {
  const absent = memory({ current: null });
  const missing = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: absent.repository,
  });
  assert.deepEqual({ status: missing.status, code: missing.code },
    { status: 404, code: 'preincident_backup_missing' });
  assert.equal(absent.row, null);
  const corrupt = memory({ current: null,
    backup: { ...snapshot(), content_sha256: '0'.repeat(64) } });
  const invalid = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: corrupt.repository,
  });
  assert.equal(invalid.code, 'snapshot_integrity_failed');
  assert.equal(corrupt.row, null);
  const otherOwner = noteScopeOwnerId(A);
  const conflict = memory({ current: { ...original, owner_id: otherOwner },
    backup: snapshot() });
  const denied = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: conflict.repository,
  });
  assert.equal(denied.code, 'owner_conflict');
  assert.equal(conflict.row.owner_id, otherOwner);
  assert.equal((await restoreOneJudgeBNote({
    identity: A, noteId: id, repository: conflict.repository,
  })).status, 403);
  assert.equal((await restoreOneJudgeBNote({
    identity: B, noteId: 'bad', repository: conflict.repository,
  })).status, 400);
});
test('already restored note remains unchanged, existing audit entries preserved', async () => {
  const db = memory({ backup: snapshot() });
  db.audits.push({ event_kind: 'earlier_audit' });
  const first = await restoreOneJudgeBNote({ identity: B, noteId: id,
    repository: db.repository });
  const second = await restoreOneJudgeBNote({ identity: B, noteId: id,
    repository: db.repository });
  assert.equal(first.mode, 'unchanged');
  assert.equal(second.mode, 'unchanged');
  assert.equal(db.audits.length, 5);
  assert.equal(db.audits[0].event_kind, 'earlier_audit');
});

test('backup creation re-reads persisted bytes; mismatch or missing row fails closed', async () => {
  const db = memory();
  await backupCreatedJudgeBNote({ identity: B, note: original, repository: db.repository });
  assert.equal((await readVerifiedBackup(B, id, db.repository)).content_sha256,
    sha256(original.content));
  const failing = memory();
  const missing = {
    ...failing.repository, findBackup: async () => null,
  };
  await assert.rejects(
    backupCreatedJudgeBNote({ identity: B, note: original, repository: missing }),
    /stage10_verified_backup_missing_or_invalid/u,
  );
  const changed = memory();
  const tampered = { ...changed.repository, findBackup: async () => ({
    ...snapshot(), title: 'wrong',
  }) };
  await assert.rejects(
    backupCreatedJudgeBNote({ identity: B, note: original, repository: tampered }),
    /stage10_backup_readback_mismatch/u,
  );
});

test('preseeded judge B row is snapshotted and read back before first mutation', async () => {
  const db = memory();
  const first = await backupBeforeJudgeBMutation({
    identity: B, note: original, repository: db.repository,
  });
  assert.equal(first.saved, true);
  db.row.content = 'changed in memory';
  const second = await backupBeforeJudgeBMutation({
    identity: B, note: db.row, repository: db.repository,
  });
  assert.equal(second.saved, false);
  assert.equal(db.backup.content, original.content);
  assert.equal(db.audits.filter(x => x.event_kind === 'backup_created').length, 1);
  const restored = await restoreOneJudgeBNote({
    identity: B, noteId: id, repository: db.repository,
  });
  assert.equal(restored.mode, 'repaired');
  assert.equal(db.row.content, original.content);
});

test('before-mutation capture refuses missing or invalid DB read-back; A not eligible', async () => {
  const db = memory();
  const bad = { ...db.repository, findBackup: async () => null };
  await assert.rejects(backupBeforeJudgeBMutation({
    identity: B, note: original, repository: bad,
  }), /stage10_verified_backup_missing_or_invalid/u);
  const ignored = await backupBeforeJudgeBMutation({
    identity: A, note: original, repository: db.repository,
  });
  assert.deepEqual(ignored, { skipped: true });
});

test('Postgres timestamptz Z versus +00:00 does not cause a spurious restore mismatch', async () => {
  const db = memory({
    current: { ...original, created_at: '2026-10-01T00:00:00+00:00' },
    backup: { ...snapshot(), note_created_at: created_at,
      captured_at: '2026-10-01T00:01:00+00:00' },
  });
  let writes = 0;
  const repo = {
    ...db.repository,
    updateOwnedNote: async () => { writes++; throw new Error('unnecessary_write'); },
    insertOwnedNote: async () => { writes++; throw new Error('unnecessary_write'); },
  };
  const result = await restoreOneJudgeBNote({ identity: B, noteId: id, repository: repo });
  assert.equal(result.status, 200);
  assert.equal(result.mode, 'unchanged');
  assert.equal(writes, 0);
  assert.equal(sameStoredInstant(created_at, db.row.created_at), true);
});

test('tampered or missing backup on second read aborts before a write', async () => {
  for (const drift of [null, { ...snapshot(), content: 'changed' }]) {
    const db = memory({ current: { ...original, content: 'injured' }, backup: snapshot() });
    let reads = 0, writes = 0;
    const repo = {
      ...db.repository,
      findBackup: async () => ++reads === 1 ? snapshot() : drift,
      updateOwnedNote: async () => { writes++; throw new Error('unsafe_write'); },
      insertOwnedNote: async () => { writes++; throw new Error('unsafe_write'); },
    };
    const result = await restoreOneJudgeBNote({ identity: B, noteId: id, repository: repo });
    assert.equal(result.status, 409);
    assert.equal(result.code, 'backup_changed_before_restore');
    assert.equal(writes, 0);
    assert.equal(db.row.content, 'injured');
    assert.deepEqual(db.audits.map(x => x.event_kind),
      ['restore_requested', 'restore_rejected']);
  }
});

test('post-restore verification fails if stored ID, owner or content differ', async () => {
  const badContents = [
    { id: '123e4567-e89b-42d3-a456-426614174003' },
    { owner_id: noteScopeOwnerId(A) },
    { content: 'not recovered' },
  ];
  for (const wrong of badContents) {
    const db = memory({ current: { ...original, content: 'injured' },
      backup: snapshot() });
    const repo = {
      ...db.repository,
      findNoteById: async () => ({ ...db.row, ...wrong }),
    };
    const result = await restoreOneJudgeBNote({ identity: B, noteId: id, repository: repo });
    // The wrong-owner variant can correctly fail even before attempting a write.
    assert.ok([409, 503].includes(result.status));
    assert.notEqual(result.status, 200);
    assert.ok(db.audits.some(x => x.event_kind !== 'restore_verified'));
  }
});
