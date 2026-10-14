// Stage 12 isolated-judge bundle. Do not import earlier-stage self-checks.
// Allowed runtime: node:fs, node:path, node:fs for checkout commit identification,
// and public HTTPS GET only. Missing/unsupported checks are explicitly not_run.
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { RULE_IDS } from '../src/decider.mjs';

const root = resolve(import.meta.dirname, '..');
// Read the checkout's current commit without invoking any subprocess.
// This remains read-only, using only node:fs and node:path.
function currentCommitFromCheckout() {
  const gitDir = join(root, '.git');
  const head = readFileSync(join(gitDir, 'HEAD'), 'utf8').trim();
  if (/^[a-f0-9]{40}$/u.test(head)) return head;
  const ref = /^ref: (refs\/[a-zA-Z0-9._/-]+)$/u.exec(head)?.[1];
  if (!ref || ref.split('/').some(part => part === '..' || part === '.')) {
    throw Error('Invalid checkout HEAD reference.');
  }
  const loosePath = join(gitDir, ...ref.split('/'));
  try {
    const candidate = readFileSync(loosePath, 'utf8').trim();
    if (/^[a-f0-9]{40}$/u.test(candidate)) return candidate;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  // Some fresh clones store branch references only in packed-refs.
  const packed = readFileSync(join(gitDir, 'packed-refs'), 'utf8');
  const line = packed.split(/\r?\n/u).find(row => row.endsWith(' ' + ref));
  const candidate = line?.split(' ')[0];
  if (!/^[a-f0-9]{40}$/u.test(candidate ?? '')) throw Error('Checkout commit not found.');
  return candidate;
}

const config = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
if (config.step !== 12) throw Error('Expected stage 12 configuration.');
const commit = currentCommitFromCheckout();
// Files in the one-purpose final squash commit. The list must be updated
// if the final patch's file set changes; never invent runtime diff results.
const changedFiles = [
  'scripts/stage12-isolated-bundle.mjs',
  'test/stage12-hermetic-bundle.test.mjs',
];
if (!Array.isArray(RULE_IDS) || RULE_IDS.length === 0
    || RULE_IDS.some(x => !/^[a-z][a-z0-9_.-]{0,79}$/u.test(x))) {
  throw Error('Invalid registered rule IDs.');
}
const repoUrl = config.repoUrl;
if (typeof repoUrl !== 'string'
    || !/^https:\/\/github\.com\/[a-zA-Z0-9-]+\/[a-zA-Z0-9._-]+$/u.test(repoUrl)) {
  throw Error('Invalid GitHub repository URL.');
}
const app = new URL(config.publicAppUrl);
if (app.protocol !== 'https:' || app.username || app.password
    || app.search || app.hash || app.pathname !== '/'
    || app.hostname === 'localhost' || app.hostname.endsWith('.example')) {
  throw Error('Invalid public HTTPS app URL.');
}

// Do not send credentials, mutate data, or read private note bodies.
async function publicGet(path) {
  try {
    const response = await fetch(new URL(path, app).href, { method: 'GET' });
    return response.status;
  } catch {
    return null;
  }
}
const observedGet = (status, expected) => status === null ? 'not_run'
  : 'Observed public GET HTTP ' + status + (status === expected ? ' (expected).' : ' (unexpected).');
const notRun = (attackId, expected) => ({ attackId, expected, observed: 'not_run' });

const [staticStatus, notesStatus, noticesStatus, roomStatus] = await Promise.all([
  publicGet('/data.json'),
  publicGet('/api/notes'),
  publicGet('/api/instructor-notices'),
  publicGet('/api/war-room'),
]);
const attackAttempts = [
  {
    attackId: 'static_note_file_removed',
    expected: 'Public static note file must not be accessible (HTTP 404).',
    observed: observedGet(staticStatus, 404),
  },
  {
    attackId: 'anonymous_note_list_denied',
    expected: 'Anonymous notes GET must be refused (HTTP 401).',
    observed: observedGet(notesStatus, 401),
  },
  notRun('anonymous_note_create_denied',
    'Anonymous notes POST should be denied; write requests are not permitted in this sandbox.'),
  notRun('invalid_login_token_denied',
    'Bearer token error test was not executed by the public GET-only bundle.'),
  {
    attackId: 'anonymous_instructor_notice_read_denied',
    expected: 'Anonymous instructor notices GET must be refused (HTTP 401).',
    observed: observedGet(noticesStatus, 401),
  },
  notRun('anonymous_instructor_notice_create_denied',
    'Anonymous notice POST should be denied; write requests are not permitted in this sandbox.'),
  notRun('anonymous_note_restore_denied',
    'Anonymous restore POST should be denied; write requests are not permitted in this sandbox.'),
  notRun('stage10_safe_policy_backup_verified',
    'Previous local policy backup check is not re-executed inside the restricted sandbox.'),
  notRun('stage10_isolated_policy_restored',
    'Previous local policy restore check requires test-file changes and is not executed.'),
  notRun('stage10_local_backup_readback',
    'Previous synthetic backup readback requires a local test runner and is not executed.'),
  notRun('stage10_local_restore_tuple_match',
    'Previous synthetic restore tuple test requires a local test runner and is not executed.'),
  notRun('stage10_local_postrestore_retests',
    'Previous synthetic post-restore retest requires a local test runner and is not executed.'),
  {
    attackId: 'anonymous_war_room_read_denied',
    expected: 'Anonymous war room GET must be refused (HTTP 401).',
    observed: observedGet(roomStatus, 401),
  },
];
if (attackAttempts.length > 20 || attackAttempts.some(x =>
    typeof x.expected !== 'string' || typeof x.observed !== 'string'
    || x.expected.length > 300 || x.observed.length > 300)) {
  throw Error('Invalid attack attempt records.');
}
const explanation = 'Stage 12: built a read-only operational war room and a 1-11 stage normal/denied request matrix. This bundle executes four public HTTPS GET probes, retains actual statuses, and marks writes, private checks and historical local tests not_run. The official 41-case assault has not been independently verified.';
const bundle = {
  schema: 'aleph.defense.submission.v2', step: 12, commit, repoUrl,
  changedFiles, policyRules: [...RULE_IDS],
  attackAttempts, explanation, blockedAt: null,
  identityProvider: config.identityProvider ?? null,
  allowedRoutes: config.allowedRoutes ?? [],
  originalApiUrl: config.originalApiUrl ?? null,
  restoreRoute: config.restoreRoute ?? null,
};
mkdirSync(join(root, 'artifacts'), { recursive: true });
const output = join(root, 'artifacts', 'submission.json');
writeFileSync(output, JSON.stringify(bundle, null, 2) + '\n', 'utf8');
process.stdout.write('Stage 12 isolated submission generated: ' + output + '\n');
process.stdout.write('commit=' + commit.slice(0, 12)
  + ' checks=' + attackAttempts.length
  + ' not_run=' + attackAttempts.filter(x => x.observed === 'not_run').length + '\n');
