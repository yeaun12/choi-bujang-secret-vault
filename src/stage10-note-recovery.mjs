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

function backupLookup(snapshot) {
  return {
    judge_run_id: snapshot.judge_run_id, identity_label: snapshot.identity_label,
    note_id: snapshot.note_id, owner_id: snapshot.owner_id,
  };
}

// A returned INSERT row is not backup verification: independently SELECT the
// immutable snapshot from storage and check every required binding. The
// payload is never returned to clients or printed in logs.
export async function readVerifiedBackup(identity, noteId, repository) {
  if (!isJudgeB(identity) || typeof noteId !== 'string' || !UUID.test(noteId)) {
    throw new Error('stage10_verified_backup_identity_required');
  }
  const stored = await repository.findBackup({
    judge_run_id: identity.runId.toLowerCase(), identity_label: 'b',
    note_id: noteId.toLowerCase(), owner_id: noteScopeOwnerId(identity),
  });
  if (!validateBackup(identity, noteId, stored)) {
    throw new Error('stage10_verified_backup_missing_or_invalid');
  }
  return stored;
}

function matchesOriginal(snapshot, original) {
  return snapshot.title === original.title &&
    snapshot.content_sha256 === original.content_sha256 &&
    sha256(snapshot.content) === original.content_sha256 &&
    Date.parse(snapshot.note_created_at) === Date.parse(original.note_created_at);
}

async function captureAndVerify(identity, note, repository, reasonCode, allowExisting) {
  const proposed = snapshotFromCreatedNote(identity, note);
  if (allowExisting) {
    // A previously saved, valid pre-incident snapshot wins. Never replace it
    // with a later (possibly corrupted) note version.
    const existing = await repository.findBackup(backupLookup(proposed));
    if (existing) {
      if (!validateBackup(identity, proposed.note_id, existing)) {
        throw new Error('stage10_existing_backup_invalid');
      }
      return { saved: false, verified: true, noteId: proposed.note_id };
    }
  }
  await repository.insertBackup(proposed); // INSERT only, no UPSERT/UPDATE.
  const verified = await readVerifiedBackup(identity, proposed.note_id, repository);
  if (!matchesOriginal(verified, proposed)) {
    throw new Error('stage10_backup_readback_mismatch');
  }
  await repository.appendAudit({
    ...backupLookup(proposed), event_kind: 'backup_created',
    reason_code: reasonCode, content_sha256: proposed.content_sha256,
  });
  return { saved: true, verified: true, noteId: proposed.note_id,
    sha256: proposed.content_sha256 };
}

export async function backupCreatedJudgeBNote({ identity, note, repository }) {
  if (!isJudgeB(identity)) return { skipped: true };
  return captureAndVerify(identity, note, repository, 'initial_created_note', false);
}

// If official test B was preseeded outside our create API, capture the
// ORIGINAL B-owned row before its FIRST authenticated PUT or DELETE.
// This cannot recover a record already corrupted outside our API; do not
// treat a later read as proof of pre-attack provenance.
export async function backupBeforeJudgeBMutation({ identity, note, repository }) {
  if (!isJudgeB(identity)) return { skipped: true };
  return captureAndVerify(identity, note, repository, 'before_note_mutation', true);
}

// PostgreSQL timestamptz can return +00:00 while a JS fixture uses Z.
// Both represent the same instant; never mutate a healthy row solely
// because PostgreSQL's date string formatting differs.
export function sameStoredInstant(first, second) {
  if (typeof first !== 'string' || typeof second !== 'string') return false;
  const a = Date.parse(first);
  const b = Date.parse(second);
  return Number.isFinite(a) && Number.isFinite(b) && a === b;
}

// Validate re-read snapshots, including content/title/ID/owner and provenance
// fields. Do not rely on metadata-only checks or log sensitive contents.
function sameStoredBackup(first, second) {
  return first.judge_run_id === second.judge_run_id &&
    first.identity_label === second.identity_label &&
    first.note_id === second.note_id &&
    first.owner_id === second.owner_id &&
    first.title === second.title &&
    first.content === second.content &&
    first.content_sha256 === second.content_sha256 &&
    sameStoredInstant(first.note_created_at, second.note_created_at) &&
    sameStoredInstant(first.captured_at, second.captured_at);
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
  // Re-read the private snapshot immediately before any write. If it
  // disappeared or any protected value changed, do not restore a single byte.
  const backupAgain = await repository.findBackup(meta);
  if (!validateBackup(identity, id, backupAgain)
      || !sameStoredBackup(backup, backupAgain)) {
    await audit('restore_rejected', 'backup_changed_before_restore');
    return { status: 409, code: 'backup_changed_before_restore' };
  }
  const fields = { id, owner_id: owner, title: backupAgain.title, content: backupAgain.content,
    created_at: backupAgain.note_created_at };
  let mode = 'unchanged';
  if (!current) {
    const created = await repository.insertOwnedNote(fields);
    if (!created || created.id !== id || created.owner_id !== owner) {
      await audit('restore_failed', 'insert_conflict');
      return { status: 409, code: 'insert_conflict' };
    }
    mode = 'recreated';
  } else if (current.title !== fields.title || current.content !== fields.content
      || !sameStoredInstant(current.created_at, fields.created_at)) {
    const changed = await repository.updateOwnedNote(fields);
    if (!changed || changed.id !== id || changed.owner_id !== owner) {
      await audit('restore_failed', 'update_conflict');
      return { status: 409, code: 'update_conflict' };
    }
    mode = 'repaired';
  }
  // Verify real DB row again, never claim success merely because write returned.
  const verified = await repository.findNoteById(id);
  if (!verified || verified.id !== backupAgain.note_id || verified.owner_id !== backupAgain.owner_id
      || verified.title !== backupAgain.title
      || !sameStoredInstant(verified.created_at, backupAgain.note_created_at)
      || typeof verified.content !== 'string'
      || sha256(verified.content) !== backupAgain.content_sha256) {
    await audit('restore_failed', 'postrestore_mismatch');
    return { status: 503, code: 'postrestore_mismatch' };
  }
  await audit('restore_verified', mode, backupAgain.content_sha256);
  return { status: 200, noteId: verified.id, ownerId: verified.owner_id,
    contentSha256: sha256(verified.content), mode };
}
