// Projection-only reader for synthetic Wazuh privilege alerts.
// Never print arbitrary alert objects or sensitive raw fields.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const first = (...values) => values.find(value => value !== null && value !== undefined && value !== '');

function safeText(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  return String(value).slice(0, 500)
    .replace(/[\r\n\t\x00-\x1f]+/g, ' ')
    .replace(/\bBearer\s+\S+/gi, '[REDACTED]')
    .replace(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|session[_-]?id)\s*[:=]\s*(?:"[^"]*"|'[^']*'|\S+)/gi, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/-----BEGIN\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gi, '[REDACTED]');
}

export function projectAlert(alert) {
  const a = object(alert);
  const data = object(a.data);
  const rule = object(a.rule);
  const level = first(rule.level, a.ruleLevel);
  return {
    timestamp: safeText(first(a.timestamp, a['@timestamp'])),
    sourceAddress: safeText(first(data.srcip, data.src_ip, a.srcip, a.source?.ip)),
    account: safeText(first(data.srcuser, data.src_user, data.user, a.user)),
    ruleLevel: level == null || level === '' || !Number.isFinite(Number(level)) ? null : Number(level),
    description: safeText(first(rule.description, a.description)),
  };
}

export function projectAlerts(doc) {
  const rows = Array.isArray(doc) ? doc
    : Array.isArray(doc?.alerts) ? doc.alerts
    : Array.isArray(doc?.data?.alerts) ? doc.data.alerts : null;
  if (!rows) throw new TypeError('Expected array of privilege Wazuh alerts');
  return rows.map(projectAlert);
}

export async function readAlerts(path = 'xdr/fixtures/privilege.json') {
  const source = JSON.parse(await readFile(path, 'utf8'));
  if (source.moduleKey && source.moduleKey !== 'privilege')
    throw new Error('Wrong XDR fixture moduleKey');
  return projectAlerts(source);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const rows = await readAlerts(process.argv[2]);
    for (const row of rows) console.log(JSON.stringify(row));
    console.log(JSON.stringify({ alertCount: rows.length, extractedCount: rows.length }));
  } catch (err) {
    console.error('Cannot read privilege fixture: ' + (err?.name ?? 'Error'));
    process.exitCode = 1;
  }
}
