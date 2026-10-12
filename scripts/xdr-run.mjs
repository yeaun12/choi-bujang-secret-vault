// Local XDR-01 replay runner. It does not replace the official ALEPH judge.
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/brute-force/decide.mjs';
import { projectAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { respond } from '../xdr/brute-force/respond.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const DEFAULT_RESULT = resolve(ROOT, 'xdr/brute-force/result.json');

async function exists(path) {
  try { await access(path); return true; }
  catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

function extractAlerts(doc) {
  if (Array.isArray(doc)) return doc;
  if (Array.isArray(doc?.alerts)) return doc.alerts;
  if (Array.isArray(doc?.data?.alerts)) return doc.data.alerts;
  throw new TypeError('Expected a JSON alert array (or an alerts array in an object)');
}

export async function runBruteForce({ fixturePath, resultPath = DEFAULT_RESULT,
  stateDir = resolve(ROOT, 'xdr'), fixtureKind = 'provided-unverified', now } = {}) {
  if (!fixturePath) throw new TypeError('fixturePath required');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  const alerts = extractAlerts(fixture);
  const projected = projectAlerts(fixture);
  if (projected.length !== alerts.length) throw new Error('Alert extraction count mismatch');

  const counts = { block: 0, alert: 0, record: 0 };
  const responseCounts = { block: 0, alert: 0, record: 0 };
  const outcomes = [];
  let labeledNormalCount = 0;
  let normalBlockedCount = 0;
  for (const [index, alert] of alerts.entries()) {
    const judgment = decide(alert);
    if (!Object.hasOwn(counts, judgment?.action)) throw new Error('Invalid XDR decision action');
    if (typeof judgment.confidence !== 'number' || !Number.isFinite(judgment.confidence) ||
        judgment.confidence < 0 || judgment.confidence > 1) {
      throw new Error('Invalid XDR decision confidence');
    }
    counts[judgment.action] += 1;
    const response = await respond(alert, judgment, { stateDir, ...(now === undefined ? {} : { now }) });
    if (!Object.hasOwn(responseCounts, response.action)) throw new Error('Invalid XDR response action');
    responseCounts[response.action] += 1;
    const truth = alert?.groundTruth === 'normal' ? 'normal'
      : alert?.groundTruth === 'attack' ? 'attack'
      : alert?.groundTruth === 'ambiguous' ? 'ambiguous' : null;
    if (truth === 'normal') {
      labeledNormalCount++;
      if (judgment.action === 'block' || response.action === 'block') normalBlockedCount++;
    }
    // Store no account, raw alert, IP address, password, or token in result.json.
    outcomes.push({
      index: index + 1, action: judgment.action, responseAction: response.action,
      confidence: judgment.confidence, reason: judgment.reason,
      ...(truth ? { groundTruth: truth } : {}),
    });
  }
  const report = {
    schema: 'aleph.xdr.brute-force.result.v1',
    scenario: 'brute-force',
    fixtureKind,
    judgeVerified: false,
    total: alerts.length,
    extractedCount: projected.length,
    counts,
    responseCounts,
    labeledNormalCount,
    normalBlockedCount: labeledNormalCount ? normalBlockedCount : null,
    normalEventCheck: labeledNormalCount ? 'checked-labeled-events-only' : 'unverifiable-no-ground-truth',
    enforcement: 'local-staged-deny-rules-only; no live ZTNA IP contract',
    outcomes,
  };
  await mkdir(dirname(resultPath), { recursive: true });
  await writeFile(resultPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  return report;
}

async function cli() {
  const [scenario, option, override] = process.argv.slice(2);
  if (scenario !== 'brute-force' || (option && (option !== '--fixture' || !override))) {
    throw new Error('Usage: npm run xdr:run -- brute-force [--fixture path/to/alerts.json]');
  }
  const provided = resolve(ROOT, 'xdr/fixtures/brute-force.json');
  const demo = resolve(ROOT, 'xdr/fixtures/brute-force.demo.json');
  const fixturePath = option === '--fixture' ? resolve(override) :
    await exists(provided) ? provided : demo;
  const fixtureKind = resolve(fixturePath) === resolve(demo) ? 'synthetic' : 'provided-unverified';
  if (fixtureKind === 'synthetic') {
    console.log('NOTICE: official Wazuh fixture absent; using SYNTHETIC demonstration events only.');
  }
  const report = await runBruteForce({ fixturePath, fixtureKind });
  console.log('fixture=' + fixtureKind + ' total=' + report.total +
    ' extracted=' + report.extractedCount);
  console.log('block=' + report.counts.block + ' alert=' + report.counts.alert +
    ' record=' + report.counts.record);
  console.log('effective-block=' + report.responseCounts.block +
    ' effective-alert=' + report.responseCounts.alert +
    ' effective-record=' + report.responseCounts.record);
  console.log('normalBlocked=' + (report.normalBlockedCount ?? 'unverifiable') +
    ' judgeVerified=false (local replay only)');
  console.log('result=' + DEFAULT_RESULT);
  if (report.normalBlockedCount > 0) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli().catch(error => {
    console.error('XDR replay failed: ' + (error?.message ?? 'unknown error'));
    process.exitCode = 1;
  });
}
