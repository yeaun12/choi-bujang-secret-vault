import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

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

function jsonError(status, message) {
  return Response.json(
    { error: message },
    {
      status,
      headers: {
        'Cache-Control': 'no-store',
      },
    }
  );
}

export async function GET(request) {
  /*
   * 인증을 다른 모든 처리보다 먼저 수행한다.
   * 토큰이 없거나 유효하지 않으면 DB를 조회하지 않는다.
   */
  if (initializationFailed || !verifyLoginAuthorization || !supabase) {
    return jsonError(503, 'Server configuration is unavailable.');
  }

  const identity = await verifyLoginAuthorization(
    request.headers.get('authorization')
  );

  if (!identity) {
    return jsonError(401, 'Authentication required.');
  }

  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('created_at', { ascending: true });

  if (error) {
    return jsonError(500, 'Notes could not be loaded.');
  }

  return Response.json(
    {
      sampleMarker: config.sampleMarker,
      notes: data,
    },
    {
      status: 200,
      headers: {
        'Cache-Control': 'no-store',
      },
    }
  );
}