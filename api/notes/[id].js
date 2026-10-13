import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { traceStage8Access } from '../../src/stage8-access-trace.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { checkStoredNoteOwner, getExactNoteId, isStoredNoteOwner, noteScopeOwnerId } from '../../src/resource-api-auth.mjs';

let supabase = null;
let verifyLoginAuthorization = null;
let initializationFailed = false;

try {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    throw new Error('missing_server_configuration');
  }

  supabase = createClient(supabaseUrl, supabaseSecretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  verifyLoginAuthorization = createLoginVerifier({
    config,
    supabaseSecretKey,
  });
} catch {
  initializationFailed = true;
}

function jsonResponse(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      'Cache-Control': 'no-store',
    },
  });
}

function jsonError(status, message) {
  return jsonResponse({ error: message }, status);
}

async function authorize(request) {
  if (initializationFailed || !verifyLoginAuthorization || !supabase) {
    return {
      response: jsonError(503, 'Server configuration is unavailable.'),
    };
  }

  const identity = await verifyLoginAuthorization(
    request.headers.get('authorization')
  );

  if (!identity) {
    return {
      response: jsonError(401, 'Authentication required.'),
    };
  }

  return { identity };
}

export async function GET(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  const id = getExactNoteId(request);

  if (!id) {
    traceStage8Access(auth.identity, 'note_item_get', 'invalid_path', 400);
    return jsonError(400, 'Invalid note id.');
  }

  const { data, error } = await supabase
    .from('notes')
    .select('id, title, content, owner_id')
    .eq('id', id)
    .eq('owner_id', noteScopeOwnerId(auth.identity))
    .maybeSingle();

  if (error) {
    traceStage8Access(auth.identity, 'note_item_get', 'db_error', 500);
    return jsonError(500, 'Note could not be loaded.');
  }

  if (!data || !isStoredNoteOwner(auth.identity, data.owner_id)) {
    traceStage8Access(auth.identity, 'note_item_get', 'not_found_or_not_owner', 404);
    return jsonError(404, 'Note not found.');
  }

  traceStage8Access(auth.identity, 'note_item_get', 'owner_match', 200);
  return jsonResponse({
    id: data.id,
    title: data.title,
    body: data.content,
  });
}

export async function PUT(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  const id = getExactNoteId(request);

  if (!id) {
    return jsonError(400, 'Invalid note id.');
  }

  let input;

  try {
    input = await request.json();
  } catch {
    return jsonError(400, 'Request body must be valid JSON.');
  }

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return jsonError(400, 'Request body must be a JSON object.');
  }

  const { title, body } = input;

  if (typeof title !== 'string' || typeof body !== 'string') {
    return jsonError(400, 'Invalid note input.');
  }

  const ownership = await checkStoredNoteOwner(supabase, auth.identity, id);
  if (ownership === 'error') return jsonError(500, 'Ownership check failed.');
  if (ownership !== 'allowed') return jsonError(404, 'Note not found.');

  const { data, error } = await supabase
    .from('notes')
    .update({
      title,
      content: body,
    })
    .eq('id', id)
    .eq('owner_id', noteScopeOwnerId(auth.identity))
    .select('id, owner_id')
    .maybeSingle();

  if (error) {
    return jsonError(500, 'Note could not be updated.');
  }

  if (!data || !isStoredNoteOwner(auth.identity, data.owner_id)) {
    return jsonError(404, 'Note not found.');
  }

  return jsonResponse({ id: data.id });
}

export async function DELETE(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  const id = getExactNoteId(request);

  if (!id) {
    return jsonError(400, 'Invalid note id.');
  }

  const ownership = await checkStoredNoteOwner(supabase, auth.identity, id);
  if (ownership === 'error') return jsonError(500, 'Ownership check failed.');
  if (ownership !== 'allowed') return jsonError(404, 'Note not found.');

  const { data, error } = await supabase
    .from('notes')
    .delete()
    .eq('id', id)
    .eq('owner_id', noteScopeOwnerId(auth.identity))
    .select('id, owner_id')
    .maybeSingle();

  if (error) {
    return jsonError(500, 'Note could not be deleted.');
  }

  if (!data || !isStoredNoteOwner(auth.identity, data.owner_id)) {
    return jsonError(404, 'Note not found.');
  }

  return jsonResponse({ id: data.id });
}

async function methodNotAllowed(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  return jsonError(405, 'Method not allowed for this route.');
}

export async function POST(request) {
  return methodNotAllowed(request);
}

export async function PATCH(request) {
  return methodNotAllowed(request);
}
