// XDR-02 local web request response staging. No live WAF or SDP enforcement.
// Real blocking requires a verified source IP from the application's trusted edge.
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';

const DEFAULT_STATE_DIR = resolve(import.meta.dirname, '..');
const TTL_MS = 15 * 60 * 1000;
const SCHEMA = 'aleph.xdr.web-injection.local-deny-rules.v1';
const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const first = (...items) => items.find(value => value !== null && value !== undefined && value !== '');
const text = value => typeof value === 'string' ? value.trim() : '';
const validIp = value => typeof value === 'string' && isIP(value) !== 0 ? value : '';

function sourceIp(alert) {
  const data = obj(alert?.data);
  return validIp(text(first(data.srcip, data.src_ip, data.source_ip,
    alert?.srcip, alert?.source?.ip)));
}

function evidenceId(alert) {
  const id = first(alert?.id, alert?.alertId);
  const value = typeof id === 'string' || typeof id === 'number' ? String(id) : '';
  return /^[a-zA-Z0-9_.:-]{1,100}$/.test(value) ? value : '';
}

function paths(options = {}) {
  const root = options.stateDir ?? DEFAULT_STATE_DIR;
  return { log: join(root, 'alerts.log'), rules: join(root, 'web-injection', 'deny-rules.json') };
}

async function readRules(path) {
  try {
    const data = JSON.parse(await readFile(path, 'utf8'));
    if (data.schema !== SCHEMA || !Array.isArray(data.rules))
      throw new TypeError('invalid_web_injection_deny_schema');
    return data.rules;
  } catch (err) {
    if (err?.code === 'ENOENT') return [];
    throw err;
  }
}

async function saveRules(path, rules) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = path + '.' + process.pid + '.tmp';
  await writeFile(tmp, JSON.stringify({ schema: SCHEMA, rules }, null, 2) + '\n',
    { mode: 0o600, flag: 'w' });
  await rename(tmp, path);
}

export async function respond(alert, judgment, options = {}) {
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid_response_time');
  const decision = obj(judgment);
  const confidence = typeof decision.confidence === 'number' && Number.isFinite(decision.confidence)
    ? decision.confidence : 0;
  const reason = text(decision.reason).replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80) || 'unclassified';
  const ip = sourceIp(alert);
  const id = evidenceId(alert);
  const wantsBlock = decision.action === 'block' && confidence >= 0.85;
  const stagedBlock = Boolean(wantsBlock && ip && id);
  const action = stagedBlock ? 'block' : decision.action === 'alert' || wantsBlock ? 'alert' : 'record';
  const { log, rules } = paths(options);
  let expiresAt = null;

  if (stagedBlock) {
    const existing = await readRules(rules);
    const active = existing.filter(entry =>
      validIp(entry?.sourceIp) && Number.isFinite(Date.parse(entry?.expiresAt))
      && Date.parse(entry.expiresAt) > now);
    expiresAt = new Date(now + TTL_MS).toISOString();
    const entry = {
      ruleId: 'xdr-02:' + id,
      sourceIp: ip,
      evidenceAlertId: id,
      reason,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };
    await saveRules(rules, [...active.filter(item => item.ruleId !== entry.ruleId), entry]);
  }

  if (action === 'block' || action === 'alert') {
    await mkdir(dirname(log), { recursive: true });
    await appendFile(log, JSON.stringify({
      at: new Date(now).toISOString(),
      moduleKey: 'web-injection',
      action,
      reason,
      evidenceAlertId: id || null,
      sourceIp: ip || null,
      ...(expiresAt ? { expiresAt } : {}),
    }) + '\n', { mode: 0o600 });
    // Never log the raw URL, query arguments, cookies or request body.
  }
  return { action, stagedBlock, reason, evidenceAlertId: id || null, expiresAt };
}

export async function isDenied(trustedSourceIp, options = {}) {
  const ip = validIp(trustedSourceIp);
  if (!ip) return false;
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid_check_time');
  const rules = await readRules(paths(options).rules);
  return rules.some(rule => rule.sourceIp === ip && Date.parse(rule.expiresAt) > now);
}
