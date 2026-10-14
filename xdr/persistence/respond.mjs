// XDR-04 local ZTNA response adapter. This is NOT attached to live ingress.
// The trusted source IP MUST come from an independently authenticated edge.
// No changes are made to src/decider.mjs or its existing rule ordering.
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { decide } from './decide.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const SCHEMA = 'aleph.xdr.persistence.local-deny-rules.v1';
const TTL_MS = 15 * 60 * 1000;
const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const ip = value => typeof value === 'string' && isIP(value) !== 0 ? value : '';
const str = value => typeof value === 'string' ? value.trim() : '';
const evidence = alert => {
  const raw = alert?.id ?? alert?.alertId;
  const id = typeof raw === 'string' || typeof raw === 'number' ? String(raw) : '';
  return /^[a-zA-Z0-9_.:-]{1,100}$/.test(id) ? id : '';
};
const source = alert => {
  const data = obj(alert?.data);
  return ip(str(data.srcip || data.src_ip || data.source_ip || alert?.srcip || alert?.source?.ip));
};
const paths = options => {
  const root = options.stateDir ?? ROOT;
  return {
    rules: join(root, 'persistence', 'deny-rules.json'),
    log: join(root, 'alerts.log'),
  };
};
const clock = (options, type) => {
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid_' + type + '_time');
  return now;
};

async function readRules(file) {
  try {
    const data = JSON.parse(await readFile(file, 'utf8'));
    if (data.schema !== SCHEMA || !Array.isArray(data.rules))
      throw new TypeError('invalid_persistence_rule_schema');
    return data.rules;
  } catch (err) {
    if (err?.code === 'ENOENT') return [];
    throw err;
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
  return rules.filter(rule =>
    ip(rule?.sourceIp) &&
    typeof rule?.evidenceAlertId === 'string' &&
    Number.isFinite(Date.parse(rule?.expiresAt)) &&
    Date.parse(rule.expiresAt) > now);
}

// Only independently confirmed classifier blocks may stage a short-lived rule.
// Calling with a forged "block" for a normal fixture cannot create a deny.
export async function respond(alert, judgment, options = {}) {
  const now = clock(options, 'response');
  const checked = decide(alert);
  const supplied = obj(judgment);
  const id = evidence(alert);
  const src = source(alert);
  const wantsBlock = supplied.action === 'block' &&
    typeof supplied.confidence === 'number' && supplied.confidence >= 0.85 &&
    checked.action === 'block' && checked.confidence >= 0.85;
  const stagedBlock = Boolean(wantsBlock && id && src);
  const action = checked.action === 'record' ? 'record'
    : stagedBlock ? 'block' : 'alert';
  const reason = checked.reason; // Fixed, safe pattern name from our classifier.
  const { rules, log } = paths(options);
  let expiresAt = null;

  if (stagedBlock) {
    const existing = activeRules(await readRules(rules), now);
    expiresAt = new Date(now + TTL_MS).toISOString();
    const rule = {
      ruleId: 'xdr-04:' + id,
      sourceIp: src,
      evidenceAlertId: id,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };
    await saveRules(rules, [...existing.filter(r => r.ruleId !== rule.ruleId), rule]);
  }
  if (action !== 'record') {
    await mkdir(dirname(log), { recursive: true });
    await appendFile(log, JSON.stringify({
      at: new Date(now).toISOString(),
      moduleKey: 'persistence',
      action, reason, evidenceAlertId: id || null,
      sourceIp: src || null,
      ...(expiresAt ? { expiresAt } : {}),
    }) + '\n', { mode: 0o600 });
    // No usernames, executable paths, note content, credentials, or raw Wazuh JSON.
  }
  return { action, stagedBlock, reason, evidenceAlertId: id || null, expiresAt };
}

export async function isDenied(trustedSourceIp, options = {}) {
  const verifiedIp = ip(trustedSourceIp);
  if (!verifiedIp) return false;
  const now = clock(options, 'check');
  const active = activeRules(await readRules(paths(options).rules), now);
  return active.some(rule => rule.sourceIp === verifiedIp);
}

// A post-decision adapter for the original five-field ZTNA response.
// The caller must provide an edge-verified IP, not a user-controlled header.
// Calling this does NOT alter the application's deployed request pipeline.
export async function enforceZtnaDecision(baseDecision, trustedSourceIp, options = {}) {
  const value = obj(baseDecision);
  if (value.schema !== 'aleph.decision.v1' || !['allow', 'deny', 'step_up'].includes(value.decision))
    throw new TypeError('invalid_base_ztna_decision');
  if (value.decision !== 'allow' || !(await isDenied(trustedSourceIp, options)))
    return baseDecision;
  return {
    ...baseDecision,
    decision: 'deny',
    reasonCode: 'xdr04_persistence_quarantine',
    ruleIds: [...new Set([...(Array.isArray(value.ruleIds) ? value.ruleIds : []),
      'xdr04_persistence_quarantine'])],
  };
}
