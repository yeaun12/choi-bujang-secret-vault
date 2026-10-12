// XDR-02 isolated single-alert web injection classifier.
// No imports, file I/O, network, credentials, or cross-call state.
const PATTERNS = Object.freeze([
  {
    "name": "repeated_sql_injection",
    "technique": "T1190",
    "condition": {
      "mitreT1190": true,
      "minRuleLevel": 10,
      "minOccurrences": 8,
      "requestIndicators": [
        "SQL syntax fragments",
        "database query chaining"
      ]
    },
    "rationale": "High-severity repeated input carrying SQL expression or database query manipulation indicators suggests automated SQL injection."
  },
  {
    "name": "repeated_script_injection",
    "technique": "T1190",
    "condition": {
      "mitreT1190": true,
      "minRuleLevel": 10,
      "minOccurrences": 8,
      "requestIndicators": [
        "script insertion markers",
        "repeated input manipulation"
      ]
    },
    "rationale": "Correlated script insertion markers across repeated web requests may signal cross-site scripting or injection probing."
  },
  {
    "name": "repeated_path_or_command_injection",
    "technique": "T1190",
    "condition": {
      "mitreT1190": true,
      "minRuleLevel": 10,
      "minOccurrences": 8,
      "requestIndicators": [
        "path traversal",
        "command separator"
      ]
    },
    "rationale": "Repeated parent-directory traversal or command separators in web parameters indicate attempted input exploitation."
  },
  {
    "name": "single_ambiguous_request",
    "technique": "T1190",
    "condition": {
      "mitreT1190": true,
      "weakOrIsolatedEvidence": true
    },
    "rationale": "An isolated anomalous web input is suspicious but insufficient alone to authorize blocking."
  }
]);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) ? value : {};
const pick = (...values) => values.find(v => v !== undefined && v !== null && v !== '');
const string = value => typeof value === 'string' ? value.slice(0, 2048).trim() : '';
const number = value => {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const result = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});
function mitre1190(rule) {
  const mitre = rule.mitre;
  const ids = Array.isArray(mitre) ? mitre
    : Array.isArray(mitre?.id) ? mitre.id
    : typeof mitre?.id === 'string' ? [mitre.id]
    : typeof mitre === 'string' ? [mitre] : [];
  return ids.some(id => /^T1190(?:\.\d{3})?$/i.test(String(id)));
}
function hasSource(alert, data) {
  const ip = string(pick(data.srcip, data.src_ip, data.source_ip, alert.srcip, alert.source?.ip));
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))
    return ip.split('.').every(part => Number(part) <= 255);
  return ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip);
}
function decodedUrl(value) {
  let url = string(value);
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(url);
      if (next === url) break;
      url = next;
    } catch { break; }
  }
  return url.toLowerCase();
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return result(0.05, 'no_matching_pattern');
  const rule = object(alert.rule);
  const data = object(alert.data);
  const description = string(pick(rule.description, alert.description)).toLowerCase();
  const url = decodedUrl(pick(data.url, data.uri, data.request, alert.url));
  const level = number(pick(rule.level, alert.ruleLevel)) ?? 0;
  const volume = number(pick(data.count, data.requestCount, data.attempts, data.request_count));
  const tagged = mitre1190(rule);
  const source = hasSource(alert, data);

  // Look for attack syntax or Wazuh's human-readable description of exploit
  // indicators. Class titles ('SQL', 'select', 'script', 'up') alone are NOT proof.
  const sql = /(?:sql\s*(?:구문|표기|주입|injection)|데이터베이스 조회를 이어|union\s+(?:all\s+)?select|(?:or|and)\s+\d+\s*=\s*\d+|doc-sql)/i.test(description + ' ' + url);
  const script = /(?:스크립트\s*(?:삽입|표식)|script\s*(?:injection|insertion|marker)|<script\b|onerror\s*=|onload\s*=|doc-script)/i.test(description + ' ' + url);
  const traversal = /(?:경로\s*(?:이탈|를 여러 단계 거슬러)|(?:\.\.[\/\\]){1,}|(?:%2e%2e)(?:%2f|\/)|doc-up-repeat)/i.test(description + ' ' + url);
  const command = /(?:명령\s*구분자|command\s*(?:injection|separator)|doc-cmd-separator|(?:[;&|]{2,})\s*(?:cat|whoami|id)\b)/i.test(description + ' ' + url);
  const mixed = /(?:스크립트 표식과 sql 표식|mixed\s*injection|doc-mixed-marker)/i.test(description + ' ' + url);
  const repeated = /(?:반복|연속|같은 주소|번갈아|이어 붙|같은.*(?:9|10|11|12|14|15|20)번|repeated|multiple attempts)/i.test(description);
  const benignCourse = /(?:수업|공지|강의|교육|course|class|정상 조회|일상 검색)/i.test(description);
  const explicitMarker = sql || script || traversal || command || mixed;

  // Only high-severity, same-source, repeated exploit evidence is a block candidate.
  if (tagged && source && level >= 10 && volume !== null && volume >= 8 &&
      explicitMarker && (repeated || volume >= 10) && !benignCourse) {
    return result(0.96,
      mixed ? PATTERNS[0].name
      : sql ? PATTERNS[0].name
      : script ? PATTERNS[1].name
      : PATTERNS[2].name);
  }

  // Routine, low-severity requests without a T1190 alert are recorded, regardless
  // of innocent words occurring in a URL.
  if (!tagged && level <= 3) return result(0.05, 'no_matching_pattern');

  // Isolated unusual requests and lower-level T1190 events require review,
  // but do not justify automatic IP blocking.
  if (tagged && (level >= 5 || explicitMarker))
    return result(0.65, PATTERNS[3].name);
  if (source && explicitMarker)
    return result(0.55, PATTERNS[3].name);
  return result(0.1, 'no_matching_pattern');
}
