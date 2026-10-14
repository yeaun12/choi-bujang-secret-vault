// XDR-05 local privilege-session revoke-candidate adapter.
// Not wired to the live SDP relay or session store. The caller MUST supply an
// independently authenticated account/source-IP mapping; never raw headers.
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { decide } from './decide.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SCHEMA = 'aleph.xdr.privilege.local-deny-rules.v1';
const TTL_MS = 15 * 60 * 1000;
const object = v => v && typeof v === 'object' && !Array.isArray(v) ? v : {};
const string = v => typeof v === 'string' ? v.trim() : '';
const ip = v => typeof v === 'string' && isIP(v) !== 0 ? v : '';
const account = v => /^[a-zA-Z0-9_.@-]{1,100}$/.test(string(v)) ? string(v) : '';
const evidenceId = alert => {
  const raw = alert?.id ?? alert?.alertId;
  const value = typeof raw === 'string' || typeof raw === 'number' ? String(raw) : '';
  return /^[a-zA-Z0-9_.:-]{1,100}$/.test(value) ? value : '';
};
const sourceIp = alert => {
  const data = object(alert?.data);
  return ip(string(data.srcip || data.src_ip || data.source_ip || alert?.srcip || alert?.source?.ip));
};
const sourceAccount = alert => {
  const data = object(alert?.data);
  return account(data.srcuser || data.sourceUser || alert?.user);
};
const paths = options => {
  const dir = options.stateDir ?? ROOT;
  return { rules: join(dir, 'privilege', 'deny-rules.json'), log: join(dir, 'alerts.log') };
};
function getNow(options, label) {
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid_' + label + '_time');
  return now;
}
async function readRules(file) {
  try {
    const data = JSON.parse(await readFile(file, 'utf8'));
    if (data.schema !== SCHEMA || !Array.isArray(data.rules))
      throw new TypeError('invalid_privilege_rule_schema');
    return data.rules;
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}
async function saveRules(file, rules) {
  await mkdir(dirname(file), { recursive: true });
  const tmp = file + '.' + process.pid + '.tmp';
  await writeFile(tmp, JSON.stringify({ schema: SCHEMA, rules }, null, 2) + '\n',
    { mode: 0o600, flag: 'w' });
  await rename(tmp, file);
}
function activeRules(rules, now) {
  return rules.filter(row => account(row?.sourceAccount) &&
    ip(row?.sourceIp) && typeof row?.evidenceAlertId === 'string' &&
    Number.isFinite(Date.parse(row?.expiresAt)) &&
    Date.parse(row.expiresAt) > now);
}

// A forged "block" decision cannot revoke a normal event. Re-run the
// independent classifier before staging any account/IP-scoped rule.
export async function respond(alert, judgment, options = {}) {
  const now = getNow(options, 'response');
  const checked = decide(alert);
  const supplied = object(judgment);
  const id = evidenceId(alert);
  const who = sourceAccount(alert);
  const where = sourceIp(alert);
  const qualifies = supplied.action === 'block' &&
    typeof supplied.confidence === 'number' && Number.isFinite(supplied.confidence) &&
    supplied.confidence >= 0.85 && checked.action === 'block' &&
    checked.confidence >= 0.85;
  const stagedBlock = Boolean(qualifies && id && who && where);
  const action = checked.action === 'record' ? 'record' :
    stagedBlock ? 'block' : 'alert';
  const reason = checked.reason; // Static, non-sensitive pattern identifier.
  const { rules, log } = paths(options);
  let expiresAt = null;
  if (stagedBlock) {
    const current = activeRules(await readRules(rules), now);
    expiresAt = new Date(now + TTL_MS).toISOString();
    const entry = {
      ruleId: 'xdr-05:' + id,
      sourceAccount: who,
      sourceIp: where,
      evidenceAlertId: id,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };
    await saveRules(rules, [...current.filter(row => row.ruleId !== entry.ruleId), entry]);
  }
  if (action !== 'record') {
    await mkdir(dirname(log), { recursive: true });
    await appendFile(log, JSON.stringify({
      at: new Date(now).toISOString(),
      moduleKey: 'privilege',
      action, reason, evidenceAlertId: id || null,
      ...(expiresAt ? { expiresAt } : {}),
    }) + '\n', { mode: 0o600 });
    // Neither account/IP nor raw Wazuh message, executable, body or tokens.
  }
  return { action, stagedBlock, reason, evidenceAlertId: id || null, expiresAt };
}

// trustedIdentity must come from an authenticated SDP identity/edge mapping.
// Wazuh data.srcuser is NOT the SDP pseudonymous subjectId. Match the verified
// account AND source IP, so unrelated accounts and devices keep their access.
export async function isRevoked(trustedIdentity, options = {}) {
  const verified = object(trustedIdentity);
  const who = account(verified.account);
  const where = ip(verified.sourceIp);
  if (!who || !where) return false;
  const now = getNow(options, 'check');
  const rules = activeRules(await readRules(paths(options).rules), now);
  return rules.some(rule => rule.sourceAccount === who && rule.sourceIp === where);
}

// Wrap an already-issued valid five-field ZTNA decision. Only deny future
// requests under an authenticated mapped account; actual session token
// invalidation requires separate integration with the session issuer.
export async function enforceZtnaDecision(baseDecision, trustedIdentity, options = {}) {
  const base = object(baseDecision);
  if (base.schema !== 'aleph.decision.v1' ||
      !['allow', 'deny', 'step_up'].includes(base.decision) ||
      !Array.isArray(base.ruleIds) || !('requestId' in base))
    throw new TypeError('invalid_base_ztna_decision');
  if (base.decision !== 'allow' || !(await isRevoked(trustedIdentity, options)))
    return baseDecision;
  return {
    schema: base.schema,
    requestId: base.requestId,
    decision: 'deny',
    reasonCode: 'resource_access_denied',
    ruleIds: ['resource_scope'],
  };
}
