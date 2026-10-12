// XDR-01 isolated classifier: no imports, filesystem, network, or cross-call state.
// Patterns below mirror xdr/brute-force/patterns.json as of the bonus-xdr-01 task.
const PATTERNS = Object.freeze([
  {
    "name": "wazuh_correlated_ssh_brute_force",
    "technique": "T1110.001",
    "condition": {
      "kind": "confirmed_wazuh_correlation",
      "ruleId": "5712",
      "requireSourceAddress": true,
      "documentedRuleMeaning": "Wazuh SSH correlation: eight failed logins from one source IP in two minutes",
      "note": "Confirm the official rule identity; do not replace correlated evidence with rule.firedtimes or rule.level."
    },
    "rationale": "Wazuh documents rule 5712 for eight failed SSH logins from one IP within two minutes; repetitive password guessing matches MITRE T1110.001."
  },
  {
    "name": "repeated_failures_same_source_and_account",
    "technique": "T1110.001",
    "condition": {
      "kind": "single_alert_aggregated_failures",
      "requireSourceAddress": true,
      "requireSameAccount": true,
      "requireFailureCount": true,
      "requireBoundedTimeWindow": true,
      "note": "A single Wazuh alert must itself contain verified aggregation evidence; without it this pattern is not confirmed."
    },
    "rationale": "Repeated authentication failures concentrated on one account within a bounded interval indicate potential password guessing under MITRE T1110.001."
  },
  {
    "name": "failures_across_multiple_accounts",
    "technique": "T1110.003",
    "condition": {
      "kind": "single_alert_aggregated_failures",
      "requireSourceAddress": true,
      "requireMultipleDistinctAccounts": true,
      "requireFailureCount": true,
      "requireBoundedTimeWindow": true,
      "note": "This is a password-spraying indicator, not proof the same password was reused; never inspect or log credentials."
    },
    "rationale": "Authentication failures from one source against many accounts in a short interval can indicate password spraying under MITRE T1110.003."
  }
]);

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const objectOrEmpty = value => isObject(value) ? value : {};
const first = (...items) => items.find(value => value !== undefined && value !== null && value !== '');
const numberOrNull = value => {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};
const normalized = value => typeof value === 'string' ? value.trim() : '';
const readCount = (...items) => numberOrNull(first(...items));

function sourceIp(alert, data) {
  const value = normalized(first(
    data.srcip, data.src_ip, data.srcIp, data.source_ip, data.sourceIp,
    alert.srcip, alert.src_ip, alert.source?.ip, alert.sourceIp,
  ));
  if (!value || value.length > 128 || /^(unknown|null|undefined|none)$/i.test(value)) return '';
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every(part => Number(part) <= 255) ? value : '';
  }
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value) ? value : '';
}

function aggregateFields(alert, data) {
  return objectOrEmpty(first(
    isObject(alert.aggregation) ? alert.aggregation : undefined,
    isObject(alert.correlation) ? alert.correlation : undefined,
    isObject(alert.summary) ? alert.summary : undefined,
    isObject(data.aggregation) ? data.aggregation : undefined,
  ));
}

function makeResult(confidence, reason) {
  const score = Math.max(0, Math.min(1, confidence));
  return {
    action: score >= 0.85 ? 'block' : score >= 0.5 ? 'alert' : 'record',
    confidence: score,
    reason,
  };
}

export function decide(alert) {
  if (!isObject(alert)) return makeResult(0.05, 'no_matching_pattern');
  const data = objectOrEmpty(alert.data);
  const rule = objectOrEmpty(alert.rule);
  const description = normalized(first(rule.description, alert.description)).toLowerCase();
  const src = sourceIp(alert, data);
  const id = String(first(rule.id, alert.ruleId, '')).trim();

  // Wazuh's documented 5712 rule already correlates repeated SSH failures
  // from the SAME source IP over a bounded two-minute window.
  if (id === PATTERNS[0].condition.ruleId) {
    return src
      ? makeResult(0.97, PATTERNS[0].name)
      : makeResult(0.7, PATTERNS[0].name);
  }

  const aggregate = aggregateFields(alert, data);
  const failureCount = readCount(
    aggregate.failedAttempts, aggregate.failureCount, aggregate.failedCount,
    aggregate.failed_attempts, aggregate.failure_count, aggregate.failed_attempt_count,
  );
  const windowSeconds = readCount(
    aggregate.windowSeconds, aggregate.window_seconds,
    aggregate.timeWindowSeconds, aggregate.time_window_seconds, aggregate.timeframe,
  );
  const distinctAccounts = readCount(
    aggregate.distinctAccounts, aggregate.distinctAccountCount,
    aggregate.uniqueAccounts, aggregate.uniqueAccountCount,
    aggregate.distinct_users, aggregate.unique_users,
  );
  const sameSource = Boolean(src) && (
    aggregate.sameSourceIp === true || aggregate.sameSource === true ||
    aggregate.sourceCount === 1 || aggregate.distinctSources === 1 ||
    normalized(aggregate.sourceIp) === src ||
    normalized(aggregate.srcip) === src ||
    aggregate.scope === 'source' || aggregate.scope === 'source_account'
  );
  const sameAccount = aggregate.sameAccount === true ||
    aggregate.accountCount === 1 || distinctAccounts === 1 ||
    aggregate.scope === 'source_account';
  // A rule's firedtimes is NOT a same-IP count; rule.level is NOT proof either.
  if (sameSource && failureCount !== null && windowSeconds !== null &&
      windowSeconds > 0 && windowSeconds <= 300) {
    if (distinctAccounts !== null && distinctAccounts >= 5 &&
        failureCount >= 10 && windowSeconds <= 120) {
      return makeResult(0.9, PATTERNS[2].name);
    }
    if (sameAccount && failureCount >= 8 && windowSeconds <= 120) {
      return makeResult(0.9, PATTERNS[1].name);
    }
    if (distinctAccounts !== null && distinctAccounts >= 3 && failureCount >= 5) {
      return makeResult(0.7, PATTERNS[2].name);
    }
    if (sameAccount && failureCount >= 4) {
      return makeResult(0.65, PATTERNS[1].name);
    }
  }

  const successOnly = /(?:authentication succeeded|successful login|login successful|accepted password|logged in successfully|로그인 성공)/i.test(description)
    && !/(?:fail|brute.force|무차별|로그인 실패)/i.test(description);
  if (successOnly) return makeResult(0.05, 'no_matching_pattern');

  const technique = Array.isArray(rule.mitre?.id) ? rule.mitre.id
    : typeof rule.mitre?.id === 'string' ? [rule.mitre.id] : [];
  const mitreBrute = technique.some(item => /^T1110(?:\.\d{3})?$/i.test(String(item)));
  const multipleFailures = /(?:brute[\s-]*force|password[\s-]*spray|multiple (?:authentication |login )?fail|repeated (?:authentication |login )?fail|무차별|반복 로그인 실패)/i.test(description);
  if (src && multipleFailures && mitreBrute) return makeResult(0.7, PATTERNS[1].name);
  if (src && multipleFailures) return makeResult(0.55, PATTERNS[1].name);
  return makeResult(0.1, 'no_matching_pattern');
}
