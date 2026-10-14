// Local API integration: real handlers, real ES256 verification and HTTP.
// Only storage and the JWKS resolver are test doubles. No production credentials.
import assert from 'node:assert/strict';
import { after, before, mock, test } from 'node:test';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier as realVerifier } from '../src/verify-login.mjs';
import { noteScopeOwnerId } from '../src/resource-api-auth.mjs';
import { sha256 } from '../src/stage10-note-recovery.mjs';

const identityB = { kind: 'judge', identity: 'b', runId: randomUUID(), userId: randomUUID() };
const identityA = { ...identityB, identity: 'a' };
const originalContent = 'Synthetic original B fixture';
const tables = { notes: [], stage10_note_backups: [], stage10_restore_audit: [] };
let backupReads = 0, server, baseUrl, tokenA, tokenB;
let failNextBackupInsert = false;
let failNextAuditInsert = false;
let failNextRetestAuditInsert = false;
const backupReadsByNote = new Map();
const oldUrl = process.env.SUPABASE_URL;
const oldKey = process.env.SUPABASE_SECRET_KEY;
const networkFetch = globalThis.fetch;
let networkRetestRequests = [];
let failNextNormalRetest = false;

// Implements storage filtering and the atomic RPC transaction boundary.
const database = {
  rpc(name, input) {
    return { async single() {
      if (name !== 'stage10_create_b_note') {
        return { data: null, error: { code: '42883' } };
      }
      // A DB transaction either commits every row or rolls everything back.
      // This is a synthetic model; it is not a live PostgreSQL RPC test.
      const before = structuredClone(tables);
      try {
        const now = new Date().toISOString();
        const id = input.p_note_id ?? randomUUID();
        if (tables.notes.some(note => note.id === id)) {
          return { data: null, error: { code: '23505' } };
        }
        const note = { id, owner_id: input.p_owner_id, title: input.p_title,
          content: input.p_content, created_at: now };
        tables.notes.push(note);
        if (failNextBackupInsert) {
          failNextBackupInsert = false;
          throw new Error('synthetic_backup_insert_failure');
        }
        const snapshot = { judge_run_id: input.p_judge_run_id,
          identity_label: 'b', note_id: id, owner_id: note.owner_id,
          title: note.title, content: note.content,
          note_created_at: note.created_at, content_sha256: sha256(note.content),
          captured_at: now };
        tables.stage10_note_backups.push(snapshot);
        // Simulate an independent, verified SELECT readback within the transaction.
        backupReads++;
        backupReadsByNote.set(id, (backupReadsByNote.get(id) ?? 0) + 1);
        assert.equal(snapshot.content_sha256, sha256(snapshot.content));
        if (failNextAuditInsert) {
          failNextAuditInsert = false;
          throw new Error('synthetic_audit_insert_failure');
        }
        tables.stage10_restore_audit.push({ judge_run_id: input.p_judge_run_id,
          identity_label: 'b', note_id: id, owner_id: note.owner_id,
          event_kind: 'backup_created', reason_code: 'initial_created_note',
          content_sha256: snapshot.content_sha256, occurred_at: now });
        return { data: { note_id: id, owner_id: note.owner_id }, error: null };
      } catch {
        for (const table of Object.keys(before)) tables[table] = before[table];
        return { data: null, error: { code: 'P0001' } };
      }
    } };
  },
  from(table) {
  assert.ok(Object.hasOwn(tables, table));
  let operation = 'select', fields, limit = Infinity, columns = '*';
  const filters = [];
  const query = {
    select(value) { columns = value ?? '*'; return this; },
    eq(key, value) { filters.push(row => row[key] === value); return this; },
    limit(value) { limit = value; return this; },
    order() { return this; },
    insert(value) { operation = 'insert'; fields = value; return this; },
    update(value) { operation = 'update'; fields = value; return this; },
    delete() { operation = 'delete'; return this; },
    then(resolve, reject) { return execute(false).then(resolve, reject); },
    single() { return execute(true); },
    maybeSingle() { return execute(true); },
  };
  async function execute(single) {
    if (table === 'stage10_note_backups' && operation === 'select') backupReads++;
    if (operation === 'insert') {
      if (table === 'stage10_restore_audit' && failNextRetestAuditInsert
          && typeof fields?.reason_code === 'string' && fields.reason_code.startsWith('retest_')) {
        failNextRetestAuditInsert = false;
        return { data: null, error: { code: 'synthetic_postrestore_audit_write_failed' } };
      }
      if (table === 'stage10_note_backups' && failNextBackupInsert) {
        failNextBackupInsert = false;
        return { data: null, error: { code: 'synthetic_backup_storage_error' } };
      }
      const now = new Date().toISOString();
      const value = structuredClone(fields);
      if (table === 'notes') { value.id ??= randomUUID(); value.created_at ??= now; }
      if (table === 'stage10_note_backups') value.captured_at ??= now;
      if (table === 'stage10_restore_audit') value.occurred_at ??= now;
      const duplicate = table === 'notes' ? tables[table].some(row => row.id === value.id)
        : table === 'stage10_note_backups' && tables[table].some(row =>
          row.judge_run_id === value.judge_run_id && row.note_id === value.note_id);
      if (duplicate) return { data: null, error: { code: '23505' } };
      tables[table].push(value);
      return { data: single ? project(value) : [project(value)], error: null };
    }
    const rows = tables[table].filter(row => filters.every(filter => filter(row))).slice(0, limit);
    if (table === 'stage10_note_backups' && operation === 'select') {
      for (const row of rows) backupReadsByNote.set(row.note_id,
        (backupReadsByNote.get(row.note_id) ?? 0) + 1);
    }
    if (operation === 'update') {
      assert.equal(table, 'notes', 'Backups/audits must remain immutable');
      rows.forEach(row => Object.assign(row, fields));
    }
    if (operation === 'delete') {
      assert.equal(table, 'notes', 'Backups/audits must remain immutable');
      tables[table] = tables[table].filter(row => !rows.includes(row));
    }
    return { data: single ? rows[0] ? project(rows[0]) : null : rows.map(project), error: null };
  }
  function project(row) {
    return structuredClone(columns === '*' ? row : Object.fromEntries(
      columns.split(',').map(key => [key.trim(), row[key.trim()]])));
  }
  return query;
} };

before(async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const sign = identity => new SignJWT({ aleph_role: 'judge', aleph_run: identity.runId,
    aleph_identity: identity.identity }).setProtectedHeader({ alg: 'ES256' })
    .setSubject(identity.userId).setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname).setIssuedAt()
    .setExpirationTime('10m').sign(privateKey);
  [tokenA, tokenB] = await Promise.all([sign(identityA), sign(identityB)]);
  process.env.SUPABASE_URL = 'https://synthetic-storage.invalid';
  process.env.SUPABASE_SECRET_KEY = 'synthetic-server-config';
  mock.module('@supabase/supabase-js', { namedExports: { createClient: () => database } });
  mock.module('../src/verify-login.mjs', { namedExports: {
    createLoginVerifier: options => realVerifier({ ...options,
      judgeKeySet: async () => publicKey,
      supabaseClient: { auth: { getClaims: async () => ({ error: true }) } },
    }),
  } });
  const [collection, item, restore] = await Promise.all([
    import('../api/notes/index.js'), import('../api/notes/[id].js'), import('../api/restore.js'),
  ]);
  server = createServer(async (incoming, outgoing) => {
    try {
      const chunks = [];
      for await (const chunk of incoming) chunks.push(chunk);
      const request = new Request(baseUrl + incoming.url, { method: incoming.method,
        headers: incoming.headers,
        ...(['GET', 'HEAD'].includes(incoming.method) ? {} : { body: Buffer.concat(chunks) }),
      });
      const path = new URL(request.url).pathname;
      const handlers = path === '/api/restore' ? restore : path === '/api/notes' ? collection : item;
      const response = await handlers[incoming.method](request);
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      outgoing.writeHead(500); outgoing.end('Local harness failure');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = 'http://127.0.0.1:' + server.address().port;
  // Exercise actual Node HTTP client/server requests for restore retests.
  // Only the configured public app origin is mapped to this synthetic local
  // server. No real external service, credential or production DB is used.
  globalThis.fetch = (input, init) => {
    const parsed = new URL(String(input));
    if (parsed.origin === new URL(config.publicAppUrl).origin) {
      assert.ok(parsed.pathname.startsWith('/api/notes/'),
        'Internal retest cannot target arbitrary endpoints');
      networkRetestRequests.push({ path: parsed.pathname, query: parsed.search,
        authenticated: Boolean(init?.headers?.Authorization) });
      if (failNextNormalRetest && init?.headers?.Authorization
          && parsed.search === '') {
        failNextNormalRetest = false;
        return Promise.reject(new Error('synthetic_http_transport_failure'));
      }
      return networkFetch(baseUrl + parsed.pathname + parsed.search, init);
    }
    return networkFetch(input, init);
  };
});
after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
  globalThis.fetch = networkFetch;
  mock.restoreAll();
  if (oldUrl === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = oldUrl;
  if (oldKey === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = oldKey;
});
async function call(method, path, token = tokenB, body) {
  const response = await fetch(baseUrl + path, { method,
    headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}),
      'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() };
}
function reset() {
  for (const table of Object.keys(tables)) tables[table] = [];
  backupReads = 0;
  failNextBackupInsert = false;
  failNextAuditInsert = false;
  failNextRetestAuditInsert = false;
  failNextNormalRetest = false;
  networkRetestRequests = [];
  backupReadsByNote.clear();
}
async function seed() {
  reset();
  const a = randomUUID(), b = randomUUID(), other = randomUUID();
  for (const [id, token, body] of [[a, tokenA, 'Synthetic A fixture'],
    [b, tokenB, originalContent], [other, tokenB, 'Synthetic other B fixture']]) {
    assert.equal((await call('POST', '/api/notes', token, { id, title: 'fixture', body })).status, 201);
  }
  return { a, b, other };
}

test('full API flow: signed creation, immutable backup, mutation, preview, exact restoration and retests', async t => {
  const { a, b, other } = await seed();
  const preserved = structuredClone(tables.notes.filter(row => row.id !== b));
  const backup = structuredClone(tables.stage10_note_backups.find(row => row.note_id === b));
  const priorAudits = structuredClone(tables.stage10_restore_audit);
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'altered', body: 'Synthetic alteration' })).status, 200);
  const before = structuredClone(tables.notes.find(row => row.id === b));
  const preview = await call('POST', '/api/restore', tokenB, { noteId: b, dryRun: true });
  assert.equal(preview.status, 200);
  assert.ok(preview.body.version);
  assert.deepEqual(preview.body.changes, ['title', 'content']);
  assert.deepEqual(tables.notes.find(row => row.id === b), before);
  const result = await call('POST', '/api/restore', tokenB,
    { noteId: b, ownerId: backup.owner_id, contentSha256: backup.content_sha256 });
  assert.equal(result.status, 200);
  assert.equal(result.body.ownerId, backup.owner_id, 'Response owner must equal the stored backup owner');
  assert.equal(result.body.backup.ownerId, backup.owner_id);
  assert.equal(result.body.backup.creationAuditVerified, true);
  assert.equal(result.body.backup.creationAuditRereadBeforeRestore, true);
  assert.equal(result.body.id, backup.note_id);
  assert.equal(result.body.contentSha256, backup.content_sha256);
  assert.equal(result.body.match.all, true);
  assert.equal(result.body.retest.passed, true);
  assert.equal(result.body.retestVerified, true);
  assert.equal(networkRetestRequests.length, 5,
    'Post-restore checks must use five outbound HTTP requests');
  assert.equal(networkRetestRequests.filter(x => x.authenticated).length, 4);
  assert.equal(networkRetestRequests.filter(x => !x.authenticated).length, 1);
  assert.equal(result.body.postRestoreRetest.success, true);
  assert.equal(result.body.postRestoreRetest.executed, 5);
  assert.equal(result.body.postRestoreRetest.passed, 5);
  assert.equal(result.body.postRestoreRetest.failed, 0);
  assert.equal(result.body.postRestoreRetest.normal.length, 1);
  assert.equal(result.body.postRestoreRetest.forbidden.length, 4);
  assert.ok([...result.body.postRestoreRetest.normal,
    ...result.body.postRestoreRetest.forbidden].every(x => Number.isInteger(x.status)));
  assert.deepEqual(result.body.retests.map(check => check.result), ['passed', 'passed', 'passed', 'passed', 'passed']);
  assert.ok(backupReads >= 6);
  const row = tables.notes.find(note => note.id === b);
  assert.equal(sha256(row.content), backup.content_sha256);
  assert.deepEqual(tables.notes.filter(note => note.id !== b), preserved);
  assert.deepEqual(tables.stage10_note_backups.find(note => note.note_id === b), backup);
  assert.deepEqual(tables.stage10_restore_audit.slice(0, priorAudits.length), priorAudits);
  // Exercise normal AND forbidden actions after restoring B, not just before.
  // The response's retest summary alone does not prove old protections survive.
  const postRestore = {
    aOwnRead: (await call('GET', '/api/notes/' + a, tokenA)).status,
    bOwnRead: (await call('GET', '/api/notes/' + b, tokenB)).status,
    bOtherOwnRead: (await call('GET', '/api/notes/' + other, tokenB)).status,
    bReadA: (await call('GET', '/api/notes/' + a, tokenB)).status,
    aReadB: (await call('GET', '/api/notes/' + b, tokenA)).status,
    aUpdateB: (await call('PUT', '/api/notes/' + b, tokenA,
      { title: 'unauthorized change', body: 'must not reach B' })).status,
    aDeleteB: (await call('DELETE', '/api/notes/' + b, tokenA)).status,
    anonymousReadB: (await call('GET', '/api/notes/' + b, null)).status,
  };
  assert.deepEqual(postRestore, {
    aOwnRead: 200, bOwnRead: 200, bOtherOwnRead: 200,
    bReadA: 404, aReadB: 404, aUpdateB: 404, aDeleteB: 404,
    anonymousReadB: 401,
  }, 'Prior authentication and per-note authorization must still hold after recovery');
  assert.equal(sha256(tables.notes.find(note => note.id === b).content),
    backup.content_sha256, 'Forbidden updates must never corrupt the restored B note');
  assert.deepEqual(tables.notes.filter(note => note.id !== b), preserved);
  const retestAudit = tables.stage10_restore_audit.filter(event =>
    typeof event.reason_code === 'string' && event.reason_code.startsWith('retest_'));
  assert.equal(retestAudit.length, 5, 'Every post-restore result needs a retained audit event');
  assert.ok(retestAudit.every(event => event.event_kind === 'restore_verified'
    && event.reason_code.endsWith('_pass')));
  t.diagnostic('STAGE10_POSTRESTORE_PROOF ' + JSON.stringify({
    scope: 'local_synthetic', postRestore, persistedRetestEvents: retestAudit.length,
    otherNotesPreserved: true, restoredBHashMatchesBackup: true,
  }));
  const reloadedBackup = tables.stage10_note_backups.find(note => note.note_id === b);
  assert.ok(backupReadsByNote.get(b) >= 2);
  t.diagnostic('STAGE10_BACKUP_PROOF ' + JSON.stringify({
    scope: 'local_synthetic', id: reloadedBackup.note_id, ownerId: reloadedBackup.owner_id,
    version: reloadedBackup.captured_at, snapshotReads: backupReadsByNote.get(b),
    storedSha256: reloadedBackup.content_sha256, recomputedSha256: sha256(reloadedBackup.content),
    previewChanges: preview.body.changes,
  }));
  t.diagnostic('STAGE10_TUPLE_PROOF ' + JSON.stringify({
    scenario: 'tampered', scope: 'local_synthetic',
    backup: { id: backup.note_id, ownerId: backup.owner_id, contentSha256: backup.content_sha256 },
    restored: { id: row.id, ownerId: row.owner_id, contentSha256: sha256(row.content) },
    response: { id: result.body.id, ownerId: result.body.ownerId,
      contentSha256: result.body.contentSha256 },
  }));
});

test('deleted B note recreated from its original backup, retaining other notes and audit', async t => {
  const { b } = await seed();
  const backup = structuredClone(tables.stage10_note_backups.find(row => row.note_id === b));
  assert.equal((await call('DELETE', '/api/notes/' + b)).status, 200);
  const result = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(result.status, 200);
  assert.equal(result.body.mode, 'recreated');
  assert.equal(result.body.ownerId, noteScopeOwnerId(identityB));
  assert.equal(result.body.retest.passed, true);
  assert.equal(tables.notes.length, 3);
  const row = tables.notes.find(note => note.id === b);
  assert.equal(row.id, backup.note_id);
  assert.equal(row.owner_id, backup.owner_id);
  assert.equal(sha256(row.content), backup.content_sha256);
  t.diagnostic('STAGE10_TUPLE_PROOF ' + JSON.stringify({
    scenario: 'deleted', scope: 'local_synthetic',
    backup: { id: backup.note_id, ownerId: backup.owner_id, contentSha256: backup.content_sha256 },
    restored: { id: row.id, ownerId: row.owner_id, contentSha256: sha256(row.content) },
    response: { id: result.body.id, ownerId: result.body.ownerId,
      contentSha256: result.body.contentSha256 },
  }));
});

test('missing or corrupt backup aborts without changing notes', async () => {
  const { b } = await seed();
  const before = structuredClone(tables.notes);
  assert.equal((await call('POST', '/api/restore', tokenB, { noteId: randomUUID() })).status, 404);
  tables.stage10_note_backups.find(row => row.note_id === b).content = 'Synthetic corrupt backup';
  assert.equal((await call('POST', '/api/restore', tokenB, { noteId: b })).status, 409);
  assert.deepEqual(tables.notes, before);
});

test('A and anonymous recovery denied; owner/hash expectations cannot widen recovery', async () => {
  const { b } = await seed();
  const before = structuredClone(tables.notes);
  assert.equal((await call('POST', '/api/restore', null, { noteId: b })).status, 401);
  assert.equal((await call('POST', '/api/restore', tokenA, { noteId: b })).status, 403);
  assert.equal((await call('POST', '/api/restore', tokenB,
    { noteId: b, ownerId: noteScopeOwnerId(identityA) })).status, 409);
  assert.equal((await call('POST', '/api/restore', tokenB,
    { noteId: b, contentSha256: '0'.repeat(64) })).status, 409);
  assert.deepEqual(tables.notes, before);
});

test('unexecuted optional A check remains unexecuted while real normal and denial tests pass', async () => {
  const { a, b } = await seed();
  tables.notes = tables.notes.filter(row => row.id !== a);
  const result = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(result.status, 200);
  assert.equal(result.body.restored, true);
  assert.equal(result.body.retest.passed, true, 'Actually run required checks passed; optional A stays unexecuted');
  assert.equal(result.body.retest.complete, true);
  assert.deepEqual(result.body.retest.notRun, ['foreign_denied']);
  assert.equal(result.body.retest.executed, 4);
  assert.equal(result.body.retest.passedCount, 4);
  assert.equal(result.body.retest.failedCount, 0);
  assert.equal(result.body.retests.length, 4);
  assert.ok(result.body.retests.every(x => Number.isInteger(x.status)));
});

test('empty POST selects exactly one damaged B snapshot and restores it', async () => {
  const { b } = await seed();
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'fixture', body: 'Synthetic alteration' })).status, 200);
  const result = await call('POST', '/api/restore', tokenB);
  assert.equal(result.status, 200);
  assert.equal(result.body.id, b);
  assert.equal(result.body.contentSha256, sha256(originalContent));
});

// A failed backup must not silently leave a new B note without any safe snapshot.
test('failed judge B backup rolls back note, backup and audit atomically', async () => {
  const { a, other } = await seed();
  const notesBefore = structuredClone(tables.notes);
  const backupsBefore = structuredClone(tables.stage10_note_backups);
  const auditsBefore = structuredClone(tables.stage10_restore_audit);
  const failedId = randomUUID();
  failNextBackupInsert = true;
  const result = await call('POST', '/api/notes', tokenB,
    { id: failedId, title: 'synthetic rejected creation', body: 'do not retain without backup' });
  assert.equal(result.status, 503);
  assert.equal(tables.notes.some(note => note.id === failedId), false);
  assert.deepEqual(tables.notes, notesBefore, 'Unrelated A and B notes must not change');
  assert.deepEqual(tables.stage10_note_backups, backupsBefore, 'Previous safe backups must remain');
  assert.deepEqual(tables.stage10_restore_audit, auditsBefore, 'Previous audits must remain');
  assert.equal((await call('GET', '/api/notes/' + a, tokenA)).status, 200);
  assert.equal((await call('GET', '/api/notes/' + other, tokenB)).status, 200);
});

test('self-consistent but rewritten B backup is rejected against original audit', async () => {
  const { b } = await seed();
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'attacked', body: 'current note modified by attacker' })).status, 200);
  const notesBeforeRestore = structuredClone(tables.notes);
  const originalProof = tables.stage10_restore_audit.find(a =>
    a.note_id === b && a.event_kind === 'backup_created');
  const snapshot = tables.stage10_note_backups.find(row => row.note_id === b);
  assert.ok(originalProof && snapshot);
  snapshot.content = 'tampered backup with a matching replacement digest';
  snapshot.content_sha256 = sha256(snapshot.content);
  assert.equal(snapshot.content_sha256, sha256(snapshot.content));
  assert.notEqual(snapshot.content_sha256, originalProof.content_sha256);
  const result = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'backup_origin_not_verified');
  assert.equal(result.body.restored, false);
  assert.deepEqual(tables.notes, notesBeforeRestore, 'No note may be altered after backup provenance failure');
  assert.equal(originalProof.content_sha256, sha256(originalContent));
  assert.ok(tables.stage10_restore_audit.some(a =>
    a.note_id === b && a.event_kind === 'restore_rejected'
      && a.reason_code === 'backup_origin_not_verified'));
});

test('missing creation audit denies restore even when snapshot hash matches', async () => {
  const { b } = await seed();
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'attacked', body: 'modified text' })).status, 200);
  const before = structuredClone(tables.notes);
  tables.stage10_restore_audit = tables.stage10_restore_audit.filter(a =>
    !(a.note_id === b && a.event_kind === 'backup_created'));
  const snapshot = tables.stage10_note_backups.find(row => row.note_id === b);
  assert.equal(snapshot.content_sha256, sha256(snapshot.content));
  const result = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'backup_origin_not_verified');
  assert.deepEqual(tables.notes, before);
});

test('failed judge B audit insertion rolls back note and backup atomically', async () => {
  await seed();
  const before = structuredClone(tables);
  failNextAuditInsert = true;
  const result = await call('POST', '/api/notes', tokenB,
    { id: randomUUID(), title: 'synthetic audit rollback', body: 'atomic rollback' });
  assert.equal(result.status, 503);
  assert.deepEqual(tables, before, 'No note or backup may survive an audit insert failure');
});

test('duplicate judge B note ID preserves previous snapshots and audit', async () => {
  const { b } = await seed();
  const before = structuredClone(tables);
  const result = await call('POST', '/api/notes', tokenB,
    { id: b, title: 'synthetic duplicate', body: 'must not overwrite' });
  assert.equal(result.status, 409);
  assert.deepEqual(tables, before);
});

test('blocked outbound GET after successful restore is a failed retest, never 200', async () => {
  const { b } = await seed();
  const backup = tables.stage10_note_backups.find(row => row.note_id === b);
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'changed', body: 'modified before restore' })).status, 200);
  failNextNormalRetest = true;
  const outcome = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(outcome.status, 503, 'Post-restore HTTP verification failure must not return 200');
  assert.equal(outcome.body.restored, true, 'Restoration itself already happened');
  assert.equal(outcome.body.retestVerified, false);
  assert.equal(outcome.body.retest.passed, false);
  assert.equal(outcome.body.retest.failedCount, 1);
  assert.equal(outcome.body.retest.normal[0].status, null);
  assert.equal(outcome.body.retest.normal[0].result, 'failed');
  assert.equal(networkRetestRequests.length, 5);
  assert.equal(sha256(tables.notes.find(row => row.id === b).content),
    backup.content_sha256);
  assert.ok(tables.stage10_restore_audit.some(row =>
    row.note_id === b && row.event_kind === 'restore_failed'
      && /^retest_normal_read_network_fail$/u.test(row.reason_code)));
});

// A post-restore audit exception must never claim that an already persisted
// restoration failed. Retest evidence remains explicitly unverified.
test('retest audit write failure preserves truthful restored result without fabricated retest success', async () => {
  const { b, other } = await seed();
  const backup = structuredClone(tables.stage10_note_backups.find(row => row.note_id === b));
  const otherBefore = structuredClone(tables.notes.find(row => row.id === other));
  assert.equal((await call('PUT', '/api/notes/' + b, tokenB,
    { title: 'synthetic attack', body: 'altered after backup' })).status, 200);
  failNextRetestAuditInsert = true;
  const outcome = await call('POST', '/api/restore', tokenB, { noteId: b });
  assert.equal(outcome.status, 503, 'Unverified post-restore audit cannot return success');
  assert.equal(outcome.body.restored, true, 'Restoration already committed: must not say false');
  assert.equal(outcome.body.retestVerified, false, 'Missing audit evidence cannot be a passed retest');
  assert.equal(outcome.body.error, 'retest_evidence_unavailable');
  assert.equal(outcome.body.retest?.evidenceUnavailable, true);
  assert.equal(outcome.body.retest?.executed, null, 'Unpersisted outcomes cannot be counted as zero');
  assert.deepEqual(outcome.body.retests, [], 'Never invent unverified HTTP status evidence');
  assert.equal(outcome.body.match?.all, true, 'Restored record must still be provably original');
  assert.equal(outcome.body.backup?.contentSha256, backup.content_sha256);
  assert.equal(outcome.body.id, backup.note_id);
  assert.equal(outcome.body.ownerId, backup.owner_id);
  assert.equal(outcome.body.contentSha256, backup.content_sha256);
  assert.ok(!outcome.body.postRestoreRetest?.success, 'No fabricated success');
  assert.equal(sha256(tables.notes.find(row => row.id === b).content), backup.content_sha256);
  assert.deepEqual(tables.notes.find(row => row.id === other), otherBefore);
  assert.ok(tables.stage10_restore_audit.some(row =>
    row.note_id === b && row.event_kind === 'restore_verified'
    && row.reason_code === 'repaired'));
  assert.ok(!tables.stage10_restore_audit.some(row =>
    row.note_id === b && row.reason_code?.startsWith('retest_')),
    'Do not claim missing retest audit evidence was persisted');
});
