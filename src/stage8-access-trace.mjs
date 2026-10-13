// Temporary Stage-8 diagnosis. Do not log bearer tokens, user IDs, note IDs,
// path query strings, content, emails, or device identifiers.
const OPERATIONS = new Set(['note_item_get', 'note_list_get', 'note_create']);
const OUTCOMES = new Set(['invalid_path', 'db_error', 'not_found_or_not_owner',
  'owner_match', 'ownership_check_denied', 'own_filtered_list', 'duplicate_id', 'created']);
const HTTP_STATUSES = new Set([200, 201, 400, 403, 404, 409, 500]);

export function traceStage8Access(identity, operation, outcome, status, emit = console.info) {
  if (identity?.kind !== 'judge' || !['a', 'b'].includes(identity.identity)) return false;
  if (!OPERATIONS.has(operation) || !OUTCOMES.has(outcome) || !HTTP_STATUSES.has(status)) return false;
  try {
    emit('S08_JUDGE_ACCESS', JSON.stringify({
      kind: 'judge', actor: identity.identity, operation, outcome, status,
    }));
    return true;
  } catch {
    return false;
  }
}
