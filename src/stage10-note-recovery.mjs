// Stage 10 task 3: B-only judge fixture snapshot and one-record recovery.
// The verification boundary is createLoginVerifier; never trust browser role/owner IDs.
import { createHash } from 'node:crypto';
import { noteScopeOwnerId } from './resource-api-auth.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const SHA256 = /^[a-f0-9]{64}$/u;

export const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
export const isJudgeB = identity => identity?.kind === 'judge' && identity.identity === 'b'
  && UUID.test(identity.runId ?? '') && UUID.test(identity.userId ?? '')
  && typeof noteScopeOwnerId(identity) === 'string';

export function snapshotFromCreatedNote(identity, note) {
  if (!isJudgeB(identity) || !note || !UUID.test(note.id ?? '')
      || note.owner_id !== noteScopeOwnerId(identity)
      || typeof note.title !== 'string' || typeof note.content !== 'string'
      || typeof note.created_at !== 'string' || !Number.isFinite(Date.parse(note.created_at))) {
    throw new Error('stage10_invalid_new_b_note');
  }
  return {
    judge_run_id: identity.runId.toLowerCase(), identity_label: 'b',
    note_id: note.id.toLowerCase(), owner_id: note.owner_id,
    title: note.title, content: note.content,
    note_created_at: note.created_at, content_sha256: sha256(note.content),
  };
}

// Hash proves unmodified snapshot bytes, NOT a pre-attack capture time.
// Snapshot must be created at the original judge-B note INSERT and must
// never be updated or regenerated from a modified/deleted row.
export function validateBackup(identity, noteId, snapshot) {
  if (!isJudgeB(identity) || !UUID.test(noteId ?? '') || !snapshot
      || snapshot.judge_run_id !== identity.runId.toLowerCase()
      || snapshot.identity_label !== 'b'
      || snapshot.note_id !== noteId.toLowerCase()
      || snapshot.owner_id !== noteScopeOwnerId(identity)
      || typeof snapshot.title !== 'string'
      || typeof snapshot.content !== 'string'
      || typeof snapshot.content_sha256 !== 'string'
      || !SHA256.test(snapshot.content_sha256)
      || sha256(snapshot.content) !== snapshot.content_sha256
      || typeof snapshot.note_created_at !== 'string'
      || !Number.isFinite(Date.parse(snapshot.note_created_at))
      || typeof snapshot.captured_at !== 'string'
      || !Number.isFinite(Date.parse(snapshot.captured_at))
      || Date.parse(snapshot.captured_at) < Date.parse(snapshot.note_created_at)) {
    return false;
  }
  return true;
}

export async function backupCreatedJudgeBNote({ identity, note, repository }) {
  if (!isJudgeB(identity)) return { skipped: true };
  const snapshot = snapshotFromCreatedNote(identity, note);
  // PK (judge_run_id, note_id) blocks overwriting; no upsert/UPDATE.
  await repository.insertBackup(snapshot);
  await repository.appendAudit({
    judge_run_id: snapshot.judge_run_id, identity_label: 'b', note_id: snapshot.note_id,
    owner_id: snapshot.owner_id, event_kind: 'backup_created',
    reason_code: 'initial_created_note', content_sha256: snapshot.content_sha256,
  });
  return { saved: true, noteId: snapshot.note_id, sha256: snapshot.content_sha256 };
}

export async function restoreOneJudgeBNote({ identity, noteId, repository }) {
  if (!isJudgeB(identity)) return { status: 403, code: 'judge_b_required' };
  if (typeof noteId !== 'string' || !UUID.test(noteId)) {
    return { status: 400, code: 'invalid_note_id' };
  }
  const id = noteId.toLowerCase();
  const owner = noteScopeOwnerId(identity);
  const meta = { judge_run_id: identity.runId.toLowerCase(),
    identity_label: 'b', note_id: id, owner_id: owner };
  const audit = async (event_kind, reason_code, content_sha256 = null) =>
    repository.appendAudit({ ...meta, event_kind, reason_code, content_sha256 });
  // Audit request must be accepted before any recovery side effect.
  await audit('restore_requested', 'judge_b_requested');
  const backup = await repository.findBackup(meta);
  if (!backup) {
    await audit('restore_rejected', 'preincident_backup_missing');
    return { status: 404, code: 'preincident_backup_missing' };
  }
  if (!validateBackup(identity, id, backup)) {
    await audit('restore_rejected', 'snapshot_integrity_failed');
    return { status: 409, code: 'snapshot_integrity_failed' };
  }
  const current = await repository.findNoteById(id);
  if (current && current.owner_id !== owner) {
    await audit('restore_rejected', 'owner_conflict');
    return { status: 409, code: 'owner_conflict' };
  }
  const fields = { id, owner_id: owner, title: backup.title, content: backup.content,
    created_at: backup.note_created_at };
  let mode = 'unchanged';
  if (!current) {
    const created = await repository.insertOwnedNote(fields);
    if (!created || created.id !== id || created.owner_id !== owner) {
      await audit('restore_failed', 'insert_conflict');
      return { status: 409, code: 'insert_conflict' };
    }
    mode = 'recreated';
  } else if (current.title !== fields.title || current.content !== fields.content
      || current.created_at !== fields.created_at) {
    const changed = await repository.updateOwnedNote(fields);
    if (!changed || changed.id !== id || changed.owner_id !== owner) {
      await audit('restore_failed', 'update_conflict');
      return { status: 409, code: 'update_conflict' };
    }
    mode = 'repaired';
  }
  // Verify real DB row again, never claim success merely because write returned.
  const verified = await repository.findNoteById(id);
  if (!verified || verified.id !== id || verified.owner_id !== owner
      || verified.title !== backup.title
      || verified.created_at !== backup.note_created_at
      || typeof verified.content !== 'string'
      || sha256(verified.content) !== backup.content_sha256) {
    await audit('restore_failed', 'postrestore_mismatch');
    return { status: 503, code: 'postrestore_mismatch' };
  }
  await audit('restore_verified', mode, backup.content_sha256);
  return { status: 200, noteId: id, ownerId: owner,
    contentSha256: backup.content_sha256, mode };
}
