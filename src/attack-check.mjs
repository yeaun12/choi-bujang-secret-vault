// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.

async function hasJsonError(response) {
  if (![401, 403].includes(response.status)) {
    return false;
  }

  try {
    const data = await response.json();

    return Boolean(
      data
      && typeof data === 'object'
      && !Array.isArray(data)
      && typeof data.error === 'string'
      && data.error.trim()
    );
  } catch {
    return false;
  }
}

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5].includes(config.step)) {
    throw new Error(
      'src/attack-check.mjs currently supports stages 1 through 5.'
    );
  }

  let app;

  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error(
      'Set the actual deployment URL in aleph.config.json.'
    );
  }

  if (
    app.protocol !== 'https:'
    || app.username
    || app.password
    || app.search
    || app.hash
    || app.pathname !== '/'
    || app.hostname.endsWith('.example')
  ) {
    throw new Error(
      'Set the actual deployment URL in aleph.config.json.'
    );
  }

  if (
    typeof config.sampleMarker !== 'string'
    || !config.sampleMarker
  ) {
    throw new Error(
      'Set the sample marker in aleph.config.json.'
    );
  }

  if (config.step === 1) {
    const response = await fetch(
      new URL('/data.json', app),
      {
        redirect: 'error',
        signal: AbortSignal.timeout(10000),
      }
    );

    let visible = false;

    if (response.ok) {
      try {
        const data = await response.json();

        visible =
          data?.sampleMarker === config.sampleMarker
          && Array.isArray(data.notes)
          && data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check.
      }
    }

    return [
      {
        attackId: 'anonymous_note_read',
        expected:
          'Anonymous request can read the stage 1 public notes.',
        observed: visible
          ? `Public notes are visible (HTTP ${response.status}).`
          : `Public notes are not visible (HTTP ${response.status}).`,
      },
    ];
  }

  const staticResponse = await fetch(
    new URL('/data.json', app),
    {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }
  );

  const staticRemoved =
    staticResponse.status === 404;

  const apiResponse = await fetch(
    new URL('/api/notes', app),
    {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }
  );

  if (config.step === 2) {
    let anonymousApiVisible = false;

    if (apiResponse.ok) {
      try {
        const data = await apiResponse.json();

        anonymousApiVisible =
          data?.sampleMarker === config.sampleMarker
          && Array.isArray(data.notes)
          && data.notes.length === 4
          && data.notes.every(
            note =>
              typeof note?.title === 'string'
              && typeof note?.content === 'string'
          );
      } catch {
        // Do not expose response bodies in the submission bundle.
      }
    }

    return [
      {
        attackId: 'static_note_file_removed',
        expected:
          'The public static data file is no longer deployed.',
        observed: staticRemoved
          ? `Static data file is absent (HTTP ${staticResponse.status}).`
          : `Static data file is still reachable (HTTP ${staticResponse.status}).`,
      },
      {
        attackId: 'anonymous_api_note_read',
        expected:
          'The stage 2 server API remains anonymously readable.',
        observed: anonymousApiVisible
          ? `Anonymous API request returned 4 sample notes (HTTP ${apiResponse.status}).`
          : `Anonymous API check failed (HTTP ${apiResponse.status}).`,
      },
    ];
  }

  const anonymousGetDenied =
    await hasJsonError(apiResponse);

  const anonymousPostResponse = await fetch(
    new URL('/api/notes', app),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: '{',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }
  );

  const anonymousPostDenied =
    await hasJsonError(anonymousPostResponse);

  const invalidAuthorization =
    `Bearer ${['bad', 'token', 'value'].join('.')}`;

  const invalidTokenResponse = await fetch(
    new URL('/api/notes', app),
    {
      headers: {
        Authorization: invalidAuthorization,
      },
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }
  );

  const invalidTokenDenied =
    await hasJsonError(invalidTokenResponse);

  return [
    {
      attackId: 'static_note_file_removed',
      expected:
        'The public static data file is not deployed.',
      observed: staticRemoved
        ? `Static data file is absent (HTTP ${staticResponse.status}).`
        : `Static data file is still reachable (HTTP ${staticResponse.status}).`,
    },
    {
      attackId: 'anonymous_note_list_denied',
      expected:
        'Anonymous note-list request is rejected with a JSON authentication error.',
      observed: anonymousGetDenied
        ? `Anonymous note-list request was denied with JSON (HTTP ${apiResponse.status}).`
        : `Anonymous note-list denial check failed (HTTP ${apiResponse.status}).`,
    },
    {
      attackId: 'anonymous_note_create_denied',
      expected:
        'Authentication is checked before an anonymous malformed create request is processed.',
      observed: anonymousPostDenied
        ? `Anonymous create request was denied with JSON (HTTP ${anonymousPostResponse.status}).`
        : `Anonymous create denial check failed (HTTP ${anonymousPostResponse.status}).`,
    },
    {
      attackId: 'invalid_login_token_denied',
      expected:
        'A malformed login token cannot read the note API.',
      observed: invalidTokenDenied
        ? `Malformed login token was denied with JSON (HTTP ${invalidTokenResponse.status}).`
        : `Malformed login token denial check failed (HTTP ${invalidTokenResponse.status}).`,
    },
  ];
}
