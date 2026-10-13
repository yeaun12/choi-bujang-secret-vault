import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { traceStage8Access } from '../../src/stage8-access-trace.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { isJudgeB } from '../../src/stage10-note-recovery.mjs';
import { createJudgeBNoteAtomic } from '../../src/stage10-atomic-create.mjs';
import { isExactNoteCollection, isOwnedNoteList, noteScopeOwnerId } from '../../src/resource-api-auth.mjs';

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

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

  if (!isExactNoteCollection(request)) {
    traceStage8Access(auth.identity, 'note_list_get', 'invalid_path', 404);
    return jsonError(404, 'Resource not found.');
  }

  const { data, error } = await supabase
    .from('notes')
    .select('id, title, content, created_at, owner_id')
    .eq('owner_id', noteScopeOwnerId(auth.identity))
    .order('created_at', { ascending: true });

  if (error) {
    traceStage8Access(auth.identity, 'note_list_get', 'db_error', 500);
    return jsonError(500, 'Notes could not be loaded.');
  }

  if (!isOwnedNoteList(auth.identity, data)) {
    traceStage8Access(auth.identity, 'note_list_get', 'ownership_check_denied', 403);
    return jsonError(403, 'Resource access denied.');
  }

  traceStage8Access(auth.identity, 'note_list_get', 'own_filtered_list', 200);
  return jsonResponse(
    data.map(note => ({
      id: note.id,
      title: note.title,
      body: note.content,
    }))
  );
}

export async function POST(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  if (!isExactNoteCollection(request)) {
    return jsonError(404, 'Resource not found.');
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

  const { id, title, body } = input;

  if (
    (id !== undefined && (typeof id !== 'string' || !UUID.test(id))) ||
    typeof title !== 'string' ||
    typeof body !== 'string'
  ) {
    return jsonError(400, 'Invalid note input.');
  }

  const note = {
    owner_id: noteScopeOwnerId(auth.identity),
    title,
    content: body,
  };

  if (id !== undefined) {
    note.id = id;
  }

  // Judge B: note, verified immutable backup and audit are a single DB RPC.
  // Never use the ordinary INSERT as a fallback when that RPC is unavailable.
  if (isJudgeB(auth.identity)) {
    const result = await createJudgeBNoteAtomic({ identity: auth.identity,
      note, database: supabase });
    if (result.status !== 201) {
      if (result.status === 409) {
        traceStage8Access(auth.identity, 'note_create', 'duplicate_id', 409);
        return jsonError(409, 'A note with that id already exists.');
      }
      console.info(JSON.stringify({ stage10_backup: result.code, status: 503 }));
      return jsonError(503, 'Safe note creation is unavailable.');
    }
    traceStage8Access(auth.identity, 'note_create', 'created', 201);
    return jsonResponse({ id: result.id }, 201);
  }

  const { data, error } = await supabase
    .from('notes').insert(note).select('id').single();

  if (error) {
    if (error.code === '23505') {
      traceStage8Access(auth.identity, 'note_create', 'duplicate_id', 409);
      return jsonError(409, 'A note with that id already exists.');
    }

    traceStage8Access(auth.identity, 'note_create', 'db_error', 500);
    return jsonError(500, 'Note could not be created.');
  }

  traceStage8Access(auth.identity, 'note_create', 'created', 201);
  return jsonResponse({ id: data.id }, 201);
}

async function methodNotAllowed(request) {
  const auth = await authorize(request);

  if (auth.response) {
    return auth.response;
  }

  return jsonError(405, 'Method not allowed for this route.');
}

export async function PUT(request) {
  return methodNotAllowed(request);
}

export async function DELETE(request) {
  return methodNotAllowed(request);
}

export async function PATCH(request) {
  return methodNotAllowed(request);
}
