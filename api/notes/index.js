import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

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

  const { data, error } = await supabase
    .from('notes')
    .select('id, title, content, created_at')
    .eq('owner_id', auth.identity.userId)
    .order('created_at', { ascending: true });

  if (error) {
    return jsonError(500, 'Notes could not be loaded.');
  }

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
    owner_id: auth.identity.userId,
    title,
    content: body,
  };

  if (id !== undefined) {
    note.id = id;
  }

  const { data, error } = await supabase
    .from('notes')
    .insert(note)
    .select('id')
    .single();

  if (error) {
    if (error.code === '23505') {
      return jsonError(409, 'A note with that id already exists.');
    }

    return jsonError(500, 'Note could not be created.');
  }

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
