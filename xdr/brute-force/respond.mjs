// XDR-01 local response adapter. It does NOT modify the existing SDP decision contract.
// Deny rules are staged locally until the official ZTNA IP-to-request connector is defined.
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join, resolve } from 'node:path';

const DEFAULT_STATE_DIR = resolve(import.meta.dirname, '..');
const BLOCK_TTL_MS = 15 * 60 * 1000;
const RULE_SCHEMA = 'aleph.xdr.local-deny-rules.v1';

const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const first = (...values) => values.find(value => value !== null && value !== undefined && value !== '');
const compact = value => typeof value === 'string' ? value.trim() : '';
const validIp = value => typeof value === 'string' && isIP(value) !== 0 ? value : '';

function sourceIp(alert) {
  const data = obj(alert?.data);
  return validIp(compact(first(data.srcip, data.src_ip, data.source_ip, data.srcIp,
    alert?.srcip, alert?.src_ip, alert?.source?.ip)));
}

function alertId(alert) {
  const value = first(alert?.id, alert?.alertId);
  if (typeof value !== 'string' && typeof value !== 'number') return '';
  const id = String(value).trim();
  return /^[a-zA-Z0-9_.:-]{1,100}$/.test(id) ? id : '';
}

function isExplicitSuccess(alert) {
  const desc = compact(first(alert?.rule?.description, alert?.description)).toLowerCase();
  // A successful login can follow an attack, but success-only events must not create an IP block.
  return /(?:successful login|login successful|authentication succeeded|accepted password|로그인 성공)/i.test(desc)
    && !/(?:failure|failed|brute[ -]?force|무차별|로그인 실패)/i.test(desc);
}

function paths(options = {}) {
  const root = options.stateDir ?? DEFAULT_STATE_DIR;
  return {
    log: join(root, 'alerts.log'),
    rules: join(root, 'brute-force', 'deny-rules.json'),
  };
}

async function readRules(file) {
  try {
    const doc = JSON.parse(await readFile(file, 'utf8'));
    return doc.schema === RULE_SCHEMA && Array.isArray(doc.rules) ? doc.rules : [];
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error; // Do not silently overwrite invalid policy state.
  }
}

async function persistRules(file, rules) {
  await mkdir(resolve(file, '..'), { recursive: true });
  const tmp = file + '.' + process.pid + '.tmp';
  await writeFile(tmp, JSON.stringify({ schema: RULE_SCHEMA, rules }, null, 2) + '\n', { flag: 'w', mode: 0o600 });
  await rename(tmp, file);
}

/**
 * Apply an independent decide(alert) result. The local deny-list is NOT connected
 * to src/decider.mjs because ALEPH SDP v1 requests contain no trusted source IP.
 * Caller must supply a trusted decision result, not browser-provided input.
 */
export async function respond(alert, decision, options = {}) {
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid response time');
  const verdict = obj(decision);
  const confidence = typeof verdict.confidence === 'number' && Number.isFinite(verdict.confidence)
    ? verdict.confidence : 0;
  const reason = compact(verdict.reason).replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80) || 'unknown_pattern';
  const ip = sourceIp(alert);
  const id = alertId(alert);
  const evidenceAvailable = ip && id && !isExplicitSuccess(alert);
  const candidate = verdict.action === 'block' && confidence >= 0.85;
  const blocked = Boolean(candidate && evidenceAvailable);
  // Unverifiable block candidates are downgraded to alerts, never silently enforced.
  const action = blocked ? 'block' : verdict.action === 'alert' || candidate ? 'alert' : 'record';
  const { log, rules } = paths(options);
  let expiresAt = null;
  if (blocked) {
    const existing = await readRules(rules);
    const current = existing.filter(item => Number.isFinite(Date.parse(item?.expiresAt)) &&
      Date.parse(item.expiresAt) > now && validIp(item.sourceIp));
    expiresAt = new Date(now + BLOCK_TTL_MS).toISOString();
    const entry = { ruleId: 'xdr-01:' + id, sourceIp: ip, evidenceAlertId: id,
      reason, createdAt: new Date(now).toISOString(), expiresAt };
    // Do not remove other active rules, nor add duplicate entries for the same alert.
    const withoutDuplicate = current.filter(item => item.ruleId !== entry.ruleId);
    await persistRules(rules, [...withoutDuplicate, entry]);
  }
  if (action === 'alert' || action === 'block') {
    await mkdir(resolve(log, '..'), { recursive: true });
    const line = { at: new Date(now).toISOString(), action, reason,
      alertId: id || null, sourceIp: ip || null };
    if (expiresAt) line.expiresAt = expiresAt;
    // Never log account names, raw alert content, passwords, tokens, or session data.
    await appendFile(log, JSON.stringify(line) + '\n', { mode: 0o600 });
  }
  return { action, stagedBlock: blocked, reason, evidenceAlertId: id || null, expiresAt };
}

/**
 * Local trusted-IP evaluation used only by tests / a future official connector.
 * Never derive trustedSourceIp from an unverified user-supplied HTTP header.
 */
export async function isDenied(trustedSourceIp, options = {}) {
  const ip = validIp(trustedSourceIp);
  if (!ip) return false;
  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) throw new TypeError('invalid check time');
  const rules = await readRules(paths(options).rules);
  return rules.some(rule => rule.sourceIp === ip && Date.parse(rule.expiresAt) > now);
}
