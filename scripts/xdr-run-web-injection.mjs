// Local XDR-02 replay; not the platform judge and not a live WAF.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { decide } from '../xdr/web-injection/decide.mjs';
import { projectAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { respond } from '../xdr/web-injection/respond.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const DEFAULT_RESULT = resolve(ROOT, 'xdr/web-injection/result.json');

function extract(doc) {
  if (Array.isArray(doc)) return doc;
  if (Array.isArray(doc?.alerts)) return doc.alerts;
  if (Array.isArray(doc?.data?.alerts)) return doc.data.alerts;
  throw new TypeError('Expected web-injection Wazuh alerts array');
}

export async function runWebInjection({
  fixturePath = resolve(ROOT, 'xdr/fixtures/web-injection.json'),
  resultPath = DEFAULT_RESULT,
  stateDir = resolve(ROOT, 'xdr'),
  fixtureKind = 'course-shared-unverified',
  now,
} = {}) {
  const doc = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (doc?.moduleKey && doc.moduleKey !== 'web-injection')
    throw new Error('Wrong XDR fixture moduleKey');
  const alerts = extract(doc);
  const projections = projectAlerts(doc);
  if (projections.length !== alerts.length) throw new Error('Missing extracted alert');
  const counts = { block: 0, alert: 0, record: 0 };
  const responseCounts = { block: 0, alert: 0, record: 0 };
  const decisions = [];
  let normalLabeled = 0;
  let falseBlockLabeled = 0;

  for (const [index, alert] of alerts.entries()) {
    const judgment = decide(alert);
    if (!Object.hasOwn(counts, judgment?.action) ||
        typeof judgment.confidence !== 'number' ||
        !Number.isFinite(judgment.confidence) ||
        judgment.confidence < 0 || judgment.confidence > 1 ||
        typeof judgment.reason !== 'string') {
      throw new TypeError('Invalid web-injection XDR decision');
    }
    counts[judgment.action]++;
    const applied = await respond(alert, judgment, { stateDir, ...(now === undefined ? {} : { now }) });
    if (!Object.hasOwn(responseCounts, applied?.action))
      throw new TypeError('Invalid web-injection XDR response');
    responseCounts[applied.action]++;
    if (alert?.groundTruth === 'normal') {
      normalLabeled++;
      if (judgment.action === 'block' || applied.action === 'block') falseBlockLabeled++;
    }
    decisions.push({
      alertId: String(alert?.id ?? 'alert-' + (index + 1)),
      action: judgment.action,
      confidence: judgment.confidence,
      reason: judgment.reason,
    });
  }

  const report = {
    schema: 'aleph.xdr.result.v1',
    moduleKey: 'web-injection',
    fixtureKind,
    judgeVerified: false,
    total: alerts.length,
    extractedCount: projections.length,
    counts,
    responseCounts,
    normalEventCheck: normalLabeled ? 'labeled-only' : 'no-ground-truth-labels',
    normalBlockedCount: normalLabeled ? falseBlockLabeled : null,
    enforcement: 'local-staged-deny-rules-only; not linked to live WAF or SDP',
    decisions,
  };
  await mkdir(dirname(resultPath), { recursive: true });
  await writeFile(resultPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
  return report;
}
