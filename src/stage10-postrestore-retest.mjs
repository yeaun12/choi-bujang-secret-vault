// Stage 10: actual post-restore HTTP request checks.
// Never print or persist bearer tokens or note bodies. Only outcomes/statuses
// and content SHA-256 comparison are kept in append-only metadata audit.
import { randomUUID } from 'node:crypto';
import { sha256, isJudgeB } from './stage10-note-recovery.mjs';
import { noteScopeOwnerId } from './resource-api-auth.mjs';

const HOSTNAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export function permittedRetestOrigin(requestUrl, configuredAppUrl, deploymentHost = '') {
  const request = new URL(requestUrl);
  const production = new URL(configuredAppUrl);
  const approvedHosts = new Set([production.host]);
  // VERCEL_URL is a platform-provided deployment hostname, not a client Host header.
  if (typeof deploymentHost === 'string' && HOSTNAME.test(deploymentHost)) {
    approvedHosts.add(deploymentHost);
  }
  if (request.protocol !== 'https:' || request.username || request.password
      || request.pathname !== '/api/restore' || request.search || request.hash
      || production.protocol !== 'https:' || production.pathname !== '/'
      || production.username || production.password
      || !HOSTNAME.test(production.hostname)
      || !approvedHosts.has(request.host)) {
    throw new Error('stage10_untrusted_retest_origin');
  }
  return request.origin;
}

const RETEST_KIND = { normal_read: 'normal', anonymous_denied: 'forbidden',
  query_rejected: 'forbidden', missing_denied: 'forbidden', foreign_denied: 'forbidden' };
const RETEST_REQUEST = {
  normal_read: 'GET /api/notes/:id as B (restored note)',
  anonymous_denied: 'GET /api/notes/:id without login',
  query_rejected: 'GET /api/notes/:id?owner_id=… as B',
  missing_denied: 'GET /api/notes/:id of non-existent note as B',
  foreign_denied: "GET /api/notes/:id of A's note as B",
};
const RETEST_EXPECTED = { normal_read: '200 and body SHA-256 equals backup',
  anonymous_denied: '401', query_rejected: '400', missing_denied: '404', foreign_denied: '404' };

export async function runPostRestoreHttpRetests({
  identity, noteId, expectedSha256, authorization, requestUrl,
  configuredAppUrl, deploymentHost = '', repository, fetchImpl = fetch,
}) {
  // A verified B identity and the exact same bearer token MUST already have
  // passed createLoginVerifier at the POST restore entrypoint.
  if (!isJudgeB(identity) || !UUID.test(noteId ?? '')
      || typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(expectedSha256)
      || typeof authorization !== 'string'
      || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)) {
    throw new Error('stage10_retest_identity_required');
  }
  const origin = permittedRetestOrigin(requestUrl, configuredAppUrl, deploymentHost);
  const itemUrl = new URL('/api/notes/' + noteId, origin);
  const meta = {
    judge_run_id: identity.runId.toLowerCase(), identity_label: 'b',
    note_id: noteId.toLowerCase(), owner_id: noteScopeOwnerId(identity),
  };
  async function get(url, authenticated) {
    try {
      const response = await fetchImpl(url, {
        method: 'GET',
        headers: authenticated ? { Authorization: authorization } : {},
        redirect: 'error', signal: AbortSignal.timeout(8000),
      });
      return response;
    } catch {
      return null; // Network error is a failed test, never fabricated HTTP 401.
    }
  }
  let foreignId = null;
  try {
    const ownerA = noteScopeOwnerId({ ...identity, identity: 'a' });
    foreignId = await repository.findFirstNoteIdByOwner(ownerA);
  } catch {
    foreignId = null; // Missing A-zone fixture is explicitly unexecuted.
  }

  // This denial case is always executable, even when no judge-A fixture
  // exists. It is not labelled as an A/foreign-owner access test.
  let absentNoteId = randomUUID();
  while (absentNoteId === noteId || await repository.findNoteById(absentNoteId)) {
    absentNoteId = randomUUID();
  }
  const calls = [
    { name: 'normal_read', url: itemUrl, authenticated: true },
    { name: 'anonymous_denied', url: itemUrl, authenticated: false },
    { name: 'query_rejected',
      url: new URL(itemUrl.href + '?owner_id=unexpected'), authenticated: true },
    { name: 'missing_denied', url: new URL('/api/notes/' + absentNoteId, origin),
      authenticated: true },
  ];
  if (foreignId && UUID.test(foreignId) && foreignId !== noteId) {
    calls.push({ name: 'foreign_denied',
      url: new URL('/api/notes/' + foreignId, origin), authenticated: true });
  }
  const responses = await Promise.all(calls.map(x => get(x.url, x.authenticated)));
  const results = [];
  for (let i = 0; i < calls.length; i++) {
    const name = calls[i].name;
    const response = responses[i];
    const status = response?.status ?? null;
    let passed = false;
    if (name === 'normal_read' && status === 200) {
      try {
        const body = await response.json();
        passed = body?.id === noteId && typeof body.body === 'string'
          && sha256(body.body) === expectedSha256;
      } catch { passed = false; }
    } else if (name === 'anonymous_denied') {
      passed = status === 401;
    } else if (name === 'query_rejected') {
      passed = status === 400;
    } else if (name === 'missing_denied') {
      passed = status === 404;
    } else if (name === 'foreign_denied') {
      passed = status === 404;
    }
    // Append-only persisted evidence: outcomes and status only.
    await repository.appendAudit({
      // Reuse existing database-approved audit event kinds. The retest_
      // prefix preserves an unambiguous record of what actually ran.
      ...meta, event_kind: passed ? 'restore_verified' : 'restore_failed',
      reason_code: 'retest_' + name + '_' + (status ?? 'network') +
        '_' + (passed ? 'pass' : 'fail'),
    });
    results.push({ check: name, kind: RETEST_KIND[name], request: RETEST_REQUEST[name],
      expected: RETEST_EXPECTED[name], status, result: passed ? 'passed' : 'failed' });
  }
  // Evidence array contains only requests that truly ran. Optional fixture
  // absence remains explicitly disclosed separately, never labelled passed.
  const skipped = [];
  if (!calls.some(x => x.name === 'foreign_denied')) {
    await repository.appendAudit({
      ...meta, event_kind: 'restore_rejected',
      reason_code: 'retest_foreign_not_run_no_a_note',
    });
    skipped.push({ check: 'foreign_denied', kind: 'forbidden',
      reason: 'not_run_no_verified_a_note' });
  }
  const mandatory = ['normal_read', 'anonymous_denied', 'query_rejected'];
  const complete = mandatory.every(name => results.some(x =>
    x.check === name && Number.isInteger(x.status)));
  const passed = complete && results.every(x => x.result === 'passed');
  return { passed, complete, results, skipped,
    executed: results.length, passedCount: results.filter(x => x.result === 'passed').length,
    failedCount: results.filter(x => x.result === 'failed').length };
}
