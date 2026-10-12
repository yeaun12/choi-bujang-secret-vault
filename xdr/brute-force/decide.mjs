// XDR-01 independent per-alert classifier. No imports, file I/O or call history.
// This pattern constant matches xdr/brute-force/patterns.json.
const PATTERNS = Object.freeze([
  {
    "name": "wazuh_correlated_ssh_brute_force",
    "technique": "T1110.001",
    "condition": {
      "kind": "wazuh_correlation",
      "ruleId": "5712",
      "requireSourceAddress": true
    },
    "rationale": "Wazuh rule 5712 correlates eight failed SSH logins from the same source within two minutes."
  },
  {
    "name": "high_volume_password_guessing",
    "technique": "T1110.001",
    "condition": {
      "kind": "wazuh_alert_volume",
      "requireSourceAddress": true,
      "requireMitreT1110": true,
      "minRuleLevel": 9,
      "minFailedAttempts": 15
    },
    "rationale": "High-severity T1110 alert with at least 15 failed attempts is a clear repeated-password guessing indicator in the supplied training fixture."
  },
  {
    "name": "multi_account_password_spraying",
    "technique": "T1110.003",
    "condition": {
      "kind": "wazuh_multi_account",
      "requireSourceAddress": true,
      "requireMitreT1110": true,
      "minRuleLevel": 9,
      "minDistinctAccounts": 5,
      "requireRepeatedOrSprayingEvidence": true
    },
    "rationale": "A correlated high-severity alert showing repeated attempts across at least five distinct accounts indicates a spraying pattern without inspecting password values."
  },
  {
    "name": "low_volume_suspicious_logins",
    "technique": "T1110",
    "condition": {
      "kind": "weak_wazuh_login_signal",
      "mitreT1110OrRepeatedFailures": true,
      "requireNonRoutineEvidence": true
    },
    "rationale": "Limited failed login attempts or contextual abnormalities warrant an alert, not an automatic block."
  }
]);

const obj = v => v !== null && typeof v === 'object' && !Array.isArray(v) ? v : {};
const pick = (...items) => items.find(v => v !== undefined && v !== null && v !== '');
const text = v => typeof v === 'string' ? v.trim() : '';
const count = v => {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const score = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence,
  reason,
});

function sourceAddress(alert, data) {
  const ip = text(pick(data.srcip, data.src_ip, data.source_ip, data.srcIp,
    alert.srcip, alert.src_ip, alert.source?.ip));
  if (!ip) return '';
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))
    return ip.split('.').every(v => Number(v) <= 255) ? ip : '';
  return ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip) ? ip : '';
}

function mitreT1110(rule) {
  const mitre = rule.mitre;
  const ids = Array.isArray(mitre) ? mitre
    : Array.isArray(mitre?.id) ? mitre.id
    : typeof mitre?.id === 'string' ? [mitre.id]
    : typeof mitre === 'string' ? [mitre] : [];
  return ids.some(id => /^T1110(?:\.\d{3})?$/i.test(String(id)));
}

function distinctAccounts(raw) {
  if (Array.isArray(raw)) return new Set(raw.filter(v => typeof v === 'string' && v)).size;
  if (typeof raw === 'string')
    return new Set(raw.split(',').map(v => v.trim()).filter(Boolean)).size;
  return null;
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return score(0.05, 'no_matching_pattern');

  const data = obj(alert.data);
  const rule = obj(alert.rule);
  const description = text(pick(rule.description, alert.description)).toLowerCase();
  const id = String(pick(rule.id, alert.ruleId, '')).trim();
  const ip = sourceAddress(alert, data);
  const level = count(pick(rule.level, alert.ruleLevel)) ?? 0;
  const tagged = mitreT1110(rule);
  const failed = /실패|무차별|추측|비밀번호를 .*넣|암호.*시도|fail(?:ed|ure|ures)?|brute[\s-]*force|password[\s-]*spray|attempts?/i.test(description);
  const routine = /로그아웃|로그인 상태|세션 유지|자료실 화면|로그인이 성공|로그인.*성공|변경이 성공|successful login|authentication succeeded|accepted password|logout|session maintained/i.test(description);
  const volume = count(pick(data.count, data.failedAttempts, data.failureCount, data.failed_count));
  const accountCount = distinctAccounts(pick(data.accounts, data.users));
  const multipleAccounts = /여러 계정|서로 다른 계정|계정\s*\d+개|계정 이름을 바꿔|두 계정|multiple accounts|multiple users|password[\s-]*spray/i.test(description);
  const repeated = /연속|같은 간격|한 글자씩|이어졌|반복|쌓였|몰린|같은 비밀번호|같은 주소|brute[\s-]*force|repeat|consecutiv|spray/i.test(description);

  // Native Wazuh 5712 is already a same-source, two-minute SSH correlation.
  if (id === PATTERNS[0].condition.ruleId)
    return ip ? score(0.97, PATTERNS[0].name) : score(0.7, PATTERNS[0].name);

  // Also accept authenticated aggregation evidence contained in a single alert.
  const aggregation = obj(pick(
    alert.aggregation && typeof alert.aggregation === 'object' ? alert.aggregation : undefined,
    alert.correlation && typeof alert.correlation === 'object' ? alert.correlation : undefined,
    alert.summary && typeof alert.summary === 'object' ? alert.summary : undefined,
    data.aggregation && typeof data.aggregation === 'object' ? data.aggregation : undefined,
  ));
  const aggregateFailures = count(pick(
    aggregation.failedAttempts, aggregation.failureCount, aggregation.failedCount,
    aggregation.failed_attempts, aggregation.failure_count, aggregation.failed_attempt_count,
  ));
  const seconds = count(pick(
    aggregation.windowSeconds, aggregation.window_seconds,
    aggregation.timeWindowSeconds, aggregation.time_window_seconds, aggregation.timeframe,
  ));
  const distinct = count(pick(
    aggregation.distinctAccounts, aggregation.distinctAccountCount,
    aggregation.uniqueAccounts, aggregation.uniqueAccountCount,
    aggregation.distinct_users, aggregation.unique_users,
  ));
  const sameSource = Boolean(ip) && (
    aggregation.sameSourceIp === true || aggregation.sameSource === true ||
    aggregation.sourceCount === 1 || aggregation.distinctSources === 1 ||
    text(aggregation.sourceIp) === ip || text(aggregation.srcip) === ip ||
    aggregation.scope === 'source' || aggregation.scope === 'source_account'
  );
  const sameAccount = aggregation.sameAccount === true || aggregation.accountCount === 1 ||
    distinct === 1 || aggregation.scope === 'source_account';
  if (sameSource && aggregateFailures !== null && seconds !== null &&
      seconds > 0 && seconds <= 300) {
    if (distinct !== null && distinct >= 5 && aggregateFailures >= 10 && seconds <= 120)
      return score(0.9, PATTERNS[2].name);
    if (sameAccount && aggregateFailures >= 8 && seconds <= 120)
      return score(0.9, PATTERNS[1].name);
    if (distinct !== null && distinct >= 3 && aggregateFailures >= 5)
      return score(0.7, PATTERNS[3].name);
    if (sameAccount && aggregateFailures >= 4)
      return score(0.65, PATTERNS[3].name);
  }

  // A MITRE tag alone does not authorize blocking. The course data reports
  // aggregated failure counts in data.count and multi-user evidence in data.accounts.
  if (ip && tagged && level >= 9) {
    if (volume !== null && volume >= 15 && failed)
      return score(0.95, multipleAccounts ? PATTERNS[2].name : PATTERNS[1].name);
    if (accountCount !== null && accountCount >= 5 &&
        (multipleAccounts || repeated))
      return score(0.95, PATTERNS[2].name);
  }

  // Normal authentication activity: even a one-off failure followed by success
  // should not block the source, and low-severity non-T1110 events are recorded.
  if (!tagged && level <= 3) return score(0.05, 'no_matching_pattern');
  if (routine && !failed && level <= 4) return score(0.05, 'no_matching_pattern');

  // Weak evidence / lower-frequency failed logins are ALERT, never BLOCK.
  if (tagged && (failed || volume !== null || level >= 5))
    return score(0.65, PATTERNS[3].name);
  if (ip && (failed && (repeated || multipleAccounts)))
    return score(0.55, PATTERNS[3].name);
  return score(0.1, 'no_matching_pattern');
}
