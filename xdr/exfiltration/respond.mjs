// XDR-06 local destination-deny adapter. It is NOT wired to production SDP.
// The caller must supply edge-verified source/account/destination mappings.
// A Wazuh event does not itself authorize a live firewall or route change.
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { decide } from './decide.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SCHEMA = 'aleph.xdr.exfiltration.local-deny-rules.v1';
const TTL_MS = 15 * 60 * 1000;
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const text = value => typeof value === 'string' ? value.trim() : '';
const ip = value => typeof value === 'string' && isIP(value) ? value : '';
const account = value => /^[A-Za-z0-9_.@-]{1,100}$/.test(text(value)) ? text(value) : '';
const evidenceId = alert => {
  const raw = alert?.id ?? alert?.alertId;
  const value = typeof raw === 'string' || typeof raw === 'number' ? String(raw) : '';
  return /^[A-Za-z0-9_.:-]{1,100}$/.test(value) ? value : '';
};
const fields = alert => {
  const data = object(alert?.data);
  return {
    sourceIp: ip(text(data.srcip || data.src_ip || data.source_ip || alert?.srcip || alert?.source?.ip)),
    sourceAccount: account(data.srcuser || data.sourceUser || alert?.user),
    destinationIp: ip(text(data.dstip || data.dst_ip || data.destination_ip || alert?.dstip || alert?.destination?.ip)),
  };
};
const paths = options => {
  const dir = options.stateDir ?? ROOT;
  return { rules: join(dir, 'exfiltration', 'deny-rules.json'), log: join(dir, 'alerts.log') };
};
function timestamp(options) {
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid_exfiltration_time');
  return now;
}
async function loadRules(path) {
  try {
    const doc = JSON.parse(await readFile(path, 'utf8'));
    if (doc.schema !== SCHEMA || !Array.isArray(doc.rules))
      throw new TypeError('invalid_exfiltration_deny_schema');
    return doc.rules;
  } catch (e) {
    if (e?.code === 'ENOENT') return [];
    throw e;
  }
}
async function persist(path, rules) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = path + '.' + process.pid + '.tmp';
  await writeFile(tmp, JSON.stringify({ schema: SCHEMA, rules }, null, 2) + '\n',
    { flag: 'w', mode: 0o600 });
  await rename(tmp, path);
}
const active = (rules, now) => rules.filter(r =>
  ip(r?.sourceIp) && ip(r?.destinationIp) && account(r?.sourceAccount) &&
  typeof r.evidenceAlertId === 'string' &&
  Number.isFinite(Date.parse(r?.expiresAt)) && Date.parse(r.expiresAt) > now);

// Only a confirmed exfiltration event may create a temporary destination rule.
// Re-evaluate the individual alert to avoid trusting forged "block" responses.
export async function respond(alert, judgment, options = {}) {
  const now = timestamp(options);
  const checked = decide(alert);
  const proposed = object(judgment);
  const id = evidenceId(alert);
  const origin = fields(alert);
  const valid = proposed.action === 'block' &&
    typeof proposed.confidence === 'number' &&
    Number.isFinite(proposed.confidence) && proposed.confidence >= 0.85 &&
    checked.action === 'block' && checked.confidence >= 0.85;
  const stagedBlock = Boolean(valid && id && origin.sourceIp &&
    origin.destinationIp && origin.sourceAccount &&
    origin.sourceIp !== origin.destinationIp);
  const action = checked.action === 'record' ? 'record' :
    stagedBlock ? 'block' : 'alert';
  const reason = checked.reason; // pattern identifier, never user-controlled text
  const { rules, log } = paths(options);
  let expiresAt = null;
  if (stagedBlock) {
    const current = active(await loadRules(rules), now);
    expiresAt = new Date(now + TTL_MS).toISOString();
    const entry = {
      ruleId: 'xdr-06:' + id,
      sourceIp: origin.sourceIp,
      sourceAccount: origin.sourceAccount,
      destinationIp: origin.destinationIp,
      evidenceAlertId: id,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };
    await persist(rules, [...current.filter(r => r.ruleId !== entry.ruleId), entry]);
  }
  if (action !== 'record') {
    await mkdir(dirname(log), { recursive: true });
    await appendFile(log, JSON.stringify({
      at: new Date(now).toISOString(),
      moduleKey: 'exfiltration',
      action,
      reason,
      evidenceAlertId: id || null,
      ...(expiresAt ? { expiresAt } : {}),
    }) + '\n', { mode: 0o600 });
    // Log no account, IP, filename, file contents, request body or secrets.
  }
  return { action, stagedBlock, reason, evidenceAlertId: id || null, expiresAt };
}

// An authorized networking layer must supply all three verified fields.
// A destination IP alone MUST NOT suppress unrelated users' normal traffic.
export async function isDestinationDenied(trustedFlow, options = {}) {
  const flow = object(trustedFlow);
  const { destinationIp, sourceIp, sourceAccount } = {
    destinationIp: ip(flow.destinationIp),
    sourceIp: ip(flow.sourceIp),
    sourceAccount: account(flow.account),
  };
  if (!destinationIp || !sourceIp || !sourceAccount) return false;
  const now = timestamp(options);
  const rules = active(await loadRules(paths(options).rules), now);
  return rules.some(r => r.destinationIp === destinationIp &&
    r.sourceIp === sourceIp && r.sourceAccount === sourceAccount);
}

// Post-decision *local* adapter; it does not alter the existing decider or
// invent fields on the 18-field SDP request. No live destination telemetry is
// currently supplied by the SDP contract. Token/session revoke is not implied.
export async function enforceZtnaDecision(baseDecision, trustedFlow, options = {}) {
  const base = object(baseDecision);
  if (base.schema !== 'aleph.decision.v1' ||
      !['allow', 'deny', 'step_up'].includes(base.decision) ||
      !Array.isArray(base.ruleIds) || !('requestId' in base))
    throw new TypeError('invalid_base_ztna_decision');
  if (base.decision !== 'allow' || !(await isDestinationDenied(trustedFlow, options)))
    return baseDecision;
  return {
    schema: base.schema,
    requestId: base.requestId,
    decision: 'deny',
    reasonCode: 'resource_access_denied',
    ruleIds: ['resource_scope'],
  };
}
