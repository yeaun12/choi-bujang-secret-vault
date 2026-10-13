// Stage 10: only a signed judge-B identity may create a note with an
// immutable snapshot and an audit record in one DB transaction.
// The SQL function must exist before this API is deployed. No fallback.
import { isJudgeB } from './stage10-note-recovery.mjs';
import { noteScopeOwnerId } from './resource-api-auth.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export async function createJudgeBNoteAtomic({ identity, note, database }) {
  if (!isJudgeB(identity) || !note || note.owner_id !== noteScopeOwnerId(identity)
      || (note.id !== undefined && (typeof note.id !== 'string' || !UUID.test(note.id)))
      || typeof note.title !== 'string' || typeof note.content !== 'string'
      || typeof database?.rpc !== 'function') {
    return { status: 503, code: 'atomic_creation_unavailable' };
  }

  try {
    const { data, error } = await database.rpc('stage10_create_b_note', {
      p_judge_run_id: identity.runId.toLowerCase(),
      p_owner_id: note.owner_id,
      p_title: note.title,
      p_content: note.content,
      p_note_id: note.id ?? null,
    }).single();

    if (error) {
      return error.code === '23505'
        ? { status: 409, code: 'duplicate_note_id' }
        : { status: 503, code: 'atomic_creation_unavailable' };
    }
    if (!data || typeof data.note_id !== 'string' || !UUID.test(data.note_id)
        || data.owner_id !== note.owner_id
        || (note.id !== undefined && data.note_id.toLowerCase() !== note.id.toLowerCase())) {
      return { status: 503, code: 'atomic_creation_verification_failed' };
    }
    return { status: 201, id: data.note_id };
  } catch {
    return { status: 503, code: 'atomic_creation_unavailable' };
  }
}
