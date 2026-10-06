// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2].includes(config.step)) {
    throw new Error('src/attack-check.mjs currently supports stages 1 and 2.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('Set the actual deployment URL in aleph.config.json.');
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
    throw new Error('Set the actual deployment URL in aleph.config.json.');
  }

  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
    throw new Error('Set the sample marker in aleph.config.json.');
  }

  if (config.step === 1) {
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });

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
        expected: 'Anonymous request can read the stage 1 public notes.',
        observed: visible
          ? `Public notes are visible (HTTP ${response.status}).`
          : `Public notes are not visible (HTTP ${response.status}).`,
      },
    ];
  }

  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  const staticRemoved = staticResponse.status === 404;

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

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
      expected: 'The public static data file is no longer deployed.',
      observed: staticRemoved
        ? `Static data file is absent (HTTP ${staticResponse.status}).`
        : `Static data file is still reachable (HTTP ${staticResponse.status}).`,
    },
    {
      attackId: 'anonymous_api_note_read',
      expected: 'The stage 2 server API remains anonymously readable.',
      observed: anonymousApiVisible
        ? `Anonymous API request returned 4 sample notes (HTTP ${apiResponse.status}).`
        : `Anonymous API check failed (HTTP ${apiResponse.status}).`,
    },
  ];
}