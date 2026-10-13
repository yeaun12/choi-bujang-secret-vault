// Stage 10 task 3: narrow server-only Supabase adapter; no secrets logged.
export function stage10Repository(database) {
  const ensure = ({ data, error }) => {
    if (error) throw new Error('stage10_storage_unavailable');
    return data;
  };
  return {
    async insertBackup(snapshot) {
      ensure(await database.from('stage10_note_backups').insert(snapshot));
    },
    async appendAudit(event) {
      ensure(await database.from('stage10_restore_audit').insert(event));
    },
    async findBackup({ judge_run_id, identity_label, note_id, owner_id }) {
      return ensure(await database.from('stage10_note_backups')
        .select('judge_run_id, identity_label, note_id, owner_id, title, content, note_created_at, content_sha256, captured_at')
        .eq('judge_run_id', judge_run_id).eq('identity_label', identity_label)
        .eq('note_id', note_id).eq('owner_id', owner_id).maybeSingle());
    },
    async listBackupNoteIds({ judge_run_id, identity_label, owner_id }) {
      const rows = ensure(await database.from('stage10_note_backups').select('note_id')
        .eq('judge_run_id', judge_run_id).eq('identity_label', identity_label)
        .eq('owner_id', owner_id).limit(50));
      return (rows ?? []).map(row => row.note_id);
    },
    async findFirstNoteIdByOwner(ownerId) {
      // Read the ID of the deterministic judge-A zone only, never A's body.
      const row = ensure(await database.from('notes').select('id')
        .eq('owner_id', ownerId).limit(1).maybeSingle());
      return row?.id ?? null;
    },
    async findNoteById(id) {
      return ensure(await database.from('notes')
        .select('id, owner_id, title, content, created_at').eq('id', id).maybeSingle());
    },
    async insertOwnedNote(fields) {
      return ensure(await database.from('notes').insert(fields)
        .select('id, owner_id').maybeSingle());
    },
    async updateOwnedNote(fields) {
      const { id, owner_id, title, content, created_at } = fields;
      return ensure(await database.from('notes')
        .update({ title, content, created_at }).eq('id', id).eq('owner_id', owner_id)
        .select('id, owner_id').maybeSingle());
    },
  };
}
