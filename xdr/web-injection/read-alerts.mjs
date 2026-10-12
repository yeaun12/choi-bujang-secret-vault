// Read-only view over course Wazuh-style web alerts.
// No raw request body, credential, cookie, token or header is printed.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const pick = (...items) => items.find(item => item !== null && item !== undefined && item !== '');
function safeText(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  return String(value).slice(0, 500)
    .replace(/\bBearer\s+\S+/gi, '[REDACTED]')
    .replace(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*\S+/gi, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]');
}

export function projectAlert(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const level = pick(a.rule?.level, a.rule_level);
  return {
    timestamp: safeText(pick(a.timestamp, a['@timestamp'])),
    sourceAddress: safeText(pick(data.srcip, data.src_ip, a.srcip, a.source?.ip)),
    requestUrl: safeText(pick(data.url, data.uri, data.request, a.url)),
    ruleLevel: level === undefined ? null : Number.isFinite(Number(level)) ? Number(level) : null,
    description: safeText(pick(a.rule?.description, a.description)),
  };
}

export function projectAlerts(doc) {
  const alerts = Array.isArray(doc) ? doc : Array.isArray(doc?.alerts) ? doc.alerts
    : Array.isArray(doc?.data?.alerts) ? doc.data.alerts : null;
  if (!alerts) throw new TypeError('Expected an array of Wazuh alerts');
  return alerts.map(projectAlert);
}

export async function readAlerts(path = 'xdr/fixtures/web-injection.json') {
  const doc = JSON.parse(await readFile(path, 'utf8'));
  return projectAlerts(doc);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const rows = await readAlerts(process.argv[2]);
    for (const row of rows) console.log(JSON.stringify(row));
    console.log(JSON.stringify({ alertCount: rows.length, extractedCount: rows.length }));
  } catch (err) {
    console.error('Cannot read web injection fixture: ' + (err?.name ?? 'Error'));
    process.exitCode = 1;
  }
}
