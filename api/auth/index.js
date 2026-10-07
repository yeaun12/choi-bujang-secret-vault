import { createClient } from '@supabase/supabase-js';

const REFRESH_COOKIE = 'aleph_refresh';
const REFRESH_COOKIE_MAX_AGE =
  60 * 60 * 24 * 30;

function jsonResponse(
  body,
  status = 200,
  setCookie = null
) {
  const headers = new Headers({
    'Cache-Control': 'no-store',
  });

  if (setCookie) {
    headers.set('Set-Cookie', setCookie);
  }

  return Response.json(body, {
    status,
    headers,
  });
}

function jsonError(
  status,
  message,
  setCookie = null
) {
  return jsonResponse(
    { error: message },
    status,
    setCookie
  );
}

function createAuthClient() {
  const supabaseUrl =
    process.env.SUPABASE_URL;

  const supabaseSecretKey =
    process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return null;
  }

  return createClient(
    supabaseUrl,
    supabaseSecretKey,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    }
  );
}

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get('cookie') || '';

  for (const part of cookieHeader.split(';')) {
    const [cookieName, ...valueParts] =
      part.trim().split('=');

    if (cookieName !== name) {
      continue;
    }

    try {
      return decodeURIComponent(
        valueParts.join('=')
      );
    } catch {
      return null;
    }
  }

  return null;
}

function setRefreshCookie(refreshToken) {
  return [
    `${REFRESH_COOKIE}=${encodeURIComponent(refreshToken)}`,
    'Path=/api/auth',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${REFRESH_COOKIE_MAX_AGE}`,
  ].join('; ');
}

function clearRefreshCookie() {
  return [
    `${REFRESH_COOKIE}=`,
    'Path=/api/auth',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=0',
  ].join('; ');
}

function publicSession(session) {
  return {
    accessToken: session.access_token,
    expiresAt: session.expires_at,
  };
}

export async function POST(request) {
  const supabase = createAuthClient();

  if (!supabase) {
    return jsonError(
      503,
      'Server configuration is unavailable.'
    );
  }

  let input;

  try {
    input = await request.json();
  } catch {
    return jsonError(
      400,
      'Request body must be valid JSON.'
    );
  }

  if (
    !input
    || typeof input !== 'object'
    || Array.isArray(input)
    || typeof input.email !== 'string'
    || typeof input.password !== 'string'
  ) {
    return jsonError(
      400,
      'Invalid login input.'
    );
  }

  const { data, error } =
    await supabase.auth.signInWithPassword({
      email: input.email,
      password: input.password,
    });

  if (
    error
    || !data.session?.access_token
    || !data.session?.refresh_token
  ) {
    return jsonError(
      401,
      'Invalid email or password.'
    );
  }

  return jsonResponse(
    {
      session: publicSession(data.session),
    },
    200,
    setRefreshCookie(
      data.session.refresh_token
    )
  );
}

export async function PUT(request) {
  const supabase = createAuthClient();

  if (!supabase) {
    return jsonError(
      503,
      'Server configuration is unavailable.'
    );
  }

  const refreshToken =
    getCookie(request, REFRESH_COOKIE);

  if (!refreshToken) {
    return jsonError(
      401,
      'Authentication required.',
      clearRefreshCookie()
    );
  }

  const { data, error } =
    await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

  if (
    error
    || !data.session?.access_token
    || !data.session?.refresh_token
  ) {
    return jsonError(
      401,
      'Session refresh failed.',
      clearRefreshCookie()
    );
  }

  return jsonResponse(
    {
      session: publicSession(data.session),
    },
    200,
    setRefreshCookie(
      data.session.refresh_token
    )
  );
}

export async function DELETE(request) {
  const supabase = createAuthClient();

  if (!supabase) {
    return jsonError(
      503,
      'Server configuration is unavailable.',
      clearRefreshCookie()
    );
  }

  const authorization =
    request.headers.get('authorization');

  const token =
    typeof authorization === 'string'
    && authorization.startsWith('Bearer ')
      ? authorization
          .slice('Bearer '.length)
          .trim()
      : '';

  if (!token) {
    return jsonError(
      401,
      'Authentication required.',
      clearRefreshCookie()
    );
  }

  const { error } =
    await supabase.auth.admin.signOut(
      token,
      'local'
    );

  if (error) {
    return jsonError(
      401,
      'Sign out failed.',
      clearRefreshCookie()
    );
  }

  return jsonResponse(
    { ok: true },
    200,
    clearRefreshCookie()
  );
}
