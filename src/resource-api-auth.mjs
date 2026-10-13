import { noteResourceFromApiPath } from './resource-id.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

// The user identity must come from the server's verified login, not body or headers.
export function isStoredNoteOwner(identity, ownerId) {
  return Boolean(
    (identity?.kind === 'student' || identity?.kind === 'judge') &&
    typeof identity.userId === 'string' && UUID.test(identity.userId) &&
    typeof ownerId === 'string' && UUID.test(ownerId) &&
    identity.userId.toLowerCase() === ownerId.toLowerCase()
  );
}

export function isOwnedNoteList(identity, rows) {
  return Array.isArray(rows) &&
    rows.every((row) => isStoredNoteOwner(identity, row?.owner_id));
}

export function getExactNoteId(request) {
  let path;
  try { path = new URL(request.url).pathname; } catch { return null; }
  const resource = noteResourceFromApiPath(path);
  return resource?.resourceId.startsWith('note:') &&
    resource.resourceId !== 'note:collection'
    ? resource.resourceId.slice('note:'.length) : null;
}

export function isExactNoteCollection(request) {
  try { return new URL(request.url).pathname === '/api/notes'; }
  catch { return false; }
}

// Read the server-stored owner before changing a record. All mutations must
// ALSO retain the atomic .eq('owner_id', identity.userId) filter.
export async function checkStoredNoteOwner(supabase, identity, id) {
  if (typeof id !== 'string' || !UUID.test(id) ||
      !identity || (identity.kind !== 'student' && identity.kind !== 'judge') ||
      typeof identity.userId !== 'string' || !UUID.test(identity.userId)) {
    return 'denied';
  }
  try {
    const { data, error } = await supabase.from('notes')
      .select('owner_id').eq('id', id).maybeSingle();
    if (error) return 'error';
    return isStoredNoteOwner(identity, data?.owner_id) ? 'allowed' : 'denied';
  } catch { return 'error'; }
}
