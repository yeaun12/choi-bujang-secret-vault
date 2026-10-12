// Read-only Wazuh alert projection. Never print raw events or credential fields.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const first = (...values) => values.find(value => value !== undefined && value !== null && value !== '');

function safeText(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  return String(value).slice(0, 500)
    .replace(/\bBearer\s+\S+/gi, '[REDACTED]')
    .replace(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+/gi, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/-----BEGIN [\s\S]*?PRIVATE KEY-----/gi, '[REDACTED]');
}

export function projectAlert(alert) {
  const data = alert && typeof alert === 'object' ? alert : {};
  const fields = data.data && typeof data.data === 'object' ? data.data : {};
  const event = fields.win?.eventdata ?? {};
  const level = first(data.rule?.level, data.rule_level);
  return {
    timestamp: safeText(first(data.timestamp, data['@timestamp'], data.time)),
    sourceAddress: safeText(first(fields.srcip, fields.src_ip, fields.source_ip, fields.srcIp,
      data.srcip, data.src_ip, data.source?.ip)),
    account: safeText(first(fields.dstuser, fields.srcuser, fields.username, fields.user,
      event.targetUserName, data.username, data.account)),
    ruleLevel: Number.isFinite(Number(level)) && level !== undefined && level !== null
      ? Number(level) : null,
    description: safeText(first(data.rule?.description, data.description)),
  };
}

export function projectAlerts(document) {
  const alerts = Array.isArray(document) ? document
    : Array.isArray(document?.alerts) ? document.alerts
    : Array.isArray(document?.data?.alerts) ? document.data.alerts
    : null;
  if (!alerts) throw new TypeError('Expected a JSON array or an object containing an alerts array');
  return alerts.map(projectAlert);
}

export async function readAlerts(path) {
  const document = JSON.parse(await readFile(path, 'utf8'));
  return projectAlerts(document);
}

const invokedAsScript = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  const path = resolve(process.argv[2] || 'xdr/fixtures/brute-force.json');
  try {
    const rows = await readAlerts(path);
    for (const row of rows) console.log(JSON.stringify(row));
    console.log(JSON.stringify({ alertCount: rows.length, extractedCount: rows.length }));
  } catch (error) {
    console.error(error?.code === 'ENOENT'
      ? 'Wazuh fixture is absent. Supply xdr/fixtures/brute-force.json; no data was generated.'
      : `Cannot read Wazuh fixture: ${error?.name ?? 'Error'}`);
    process.exitCode = 1;
  }
}
