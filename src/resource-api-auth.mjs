import { createHash } from 'node:crypto';
import { noteResourceFromApiPath } from './resource-id.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

// Use only identities verified server-side by createLoginVerifier.
// The judge's signed run/identity (A or B) is a separate resource tenant,
// even if both test tokens carry the same subject UUID.
export function noteScopeOwnerId(identity) {
  if (identity?.kind === 'student' && typeof identity.userId === 'string'
      && UUID.test(identity.userId)) return identity.userId.toLowerCase();
  if (identity?.kind !== 'judge' || typeof identity.userId !== 'string'
      || !UUID.test(identity.userId) || typeof identity.runId !== 'string'
      || !UUID.test(identity.runId) || !['a', 'b'].includes(identity.identity)) {
    return null;
  }

  // Deterministic UUID-shaped partition key for service-role storage;
  // never use a request-body role or unverified client identifier.
  const digest = createHash('sha256')
    .update(['aleph.stage8.judge.notes.v1', identity.runId.toLowerCase(),
      identity.userId.toLowerCase(), identity.identity].join(':')).digest();
  digest[6] = (digest[6] & 0x0f) | 0x40;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function isStoredNoteOwner(identity, ownerId) {
  const expected = noteScopeOwnerId(identity);
  return typeof expected === 'string' && typeof ownerId === 'string'
    && UUID.test(ownerId) && expected === ownerId.toLowerCase();
}

export function isOwnedNoteList(identity, rows) {
  return Array.isArray(rows) &&
    rows.every((row) => isStoredNoteOwner(identity, row?.owner_id));
}

export function getExactNoteId(request) {
  let url;
  try { url = new URL(request.url); } catch { return null; }
  // Query-based resource selection must not silently turn into a normal read.
  if (url.search || url.hash) return null;
  const resource = noteResourceFromApiPath(url.pathname);
  return resource?.resourceId.startsWith('note:') &&
    resource.resourceId !== 'note:collection'
    ? resource.resourceId.slice('note:'.length) : null;
}

export function isExactNoteCollection(request) {
  try {
    const url = new URL(request.url);
    return url.pathname === '/api/notes' && !url.search && !url.hash;
  } catch { return false; }
}

// Read the server-stored owner before changing a record. All mutations must
// ALSO retain the atomic .eq('owner_id', identity.userId) filter.
export async function checkStoredNoteOwner(supabase, identity, id) {
  if (typeof id !== 'string' || !UUID.test(id) || !noteScopeOwnerId(identity)) {
    return 'denied';
  }
  try {
    const { data, error } = await supabase.from('notes')
      .select('owner_id').eq('id', id).maybeSingle();
    if (error) return 'error';
    return isStoredNoteOwner(identity, data?.owner_id) ? 'allowed' : 'denied';
  } catch { return 'error'; }
}
