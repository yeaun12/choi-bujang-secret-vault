// XDR-04: standalone, one-alert persistence classifier for course fixtures.
// No imports, files, network, environment state, or use of alert identifiers.
const PATTERNS = Object.freeze([
  { name: 'suspicious_autostart_registration', technique: 'T1543' },
  { name: 'suspicious_scheduled_task', technique: 'T1053' },
  { name: 'persistence_context_needs_review', technique: 'T1053/T1543' },
]);

const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const str = value => typeof value === 'string' ? value.slice(0, 4096) : '';
const numeric = value => {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const verdict = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});

function techniqueIds(rule) {
  const value = rule.mitre;
  const ids = Array.isArray(value) ? value
    : Array.isArray(value?.id) ? value.id
    : typeof value?.id === 'string' ? [value.id]
    : typeof value === 'string' ? [value] : [];
  return ids.map(String);
}

function sourceAddress(alert, data) {
  const value = str(data.srcip || data.src_ip || data.source_ip ||
    alert.srcip || alert.source?.ip).trim();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value))
    return value.split('.').every(octet => Number(octet) <= 255);
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return verdict(0.05, 'no_matching_pattern');

  const rule = obj(alert.rule);
  const data = obj(alert.data);
  const description = str(rule.description || alert.description).toLowerCase();
  const path = str(data.path || data.imagePath || data.executablePath).toLowerCase();
  const level = numeric(rule.level ?? alert.ruleLevel) ?? 0;
  const count = numeric(data.count ?? data.eventCount);
  const tagged = techniqueIds(rule).some(id => /^T(?:1053|1543)(?:\.\d{3})?$/i.test(id));
  const source = sourceAddress(alert, data);

  const service = /서비스|service/i.test(description);
  const scheduled = /예약\s*작업|scheduled[\s-]*task|task scheduler/i.test(description);
  const startup = /시작\s*(?:폴더|프로그램|항목)|startup/i.test(description);
  const persistenceMechanism = service || scheduled || startup;
  const tempPath = /(?:^|[\\/])(?:temp|tmp)[\\/]/i.test(path);
  const startupPath = /[\\/]start menu[\\/]programs[\\/]startup[\\/]/i.test(path);
  const explicitSuspicion = /서명(?:이)?\s*없|서명\s*없는|처음\s*보는|평소\s*목록에\s*없는|임의\s*문자열|수업\s*시간\s*밖|새\s*서비스|다시\s*켜도\s*남|실행\s*파일이\s*바뀌|같은\s*임시\s*파일을\s*함께|unknown|unsigned|unrecognized|untrusted/i.test(description);
  const actionEvidence = /등록|추가|실행|바뀌|변경|가리킵|남도록|만들|생성|installed|registered|created|changed|pointing|persist/i.test(description);
  const negativeEvidence = /등록은\s*없|실행된\s*기록은\s*없|읽기만\s*했|실행\s*파일은\s*그대로|평소\s*시각에\s*그대로|기존.*서명된|not\s+registered|not\s+installed|unchanged|read\s+only/i.test(description);
  const repeatedUnsignedService = service &&
    /서명\s*없는|unsigned/i.test(description) &&
    /연속|반복|repeated|consecutive/i.test(description) &&
    count !== null && count >= 3;

  // Severity and a MITRE tag alone are never authorization to block.
  // Require an identified source, a persistence mechanism, a concrete
  // suspicious change, AND corroboration from the executable path or
  // an explicitly aggregated sequence of unsigned service registrations.
  if (tagged && source && level >= 10 && persistenceMechanism &&
      explicitSuspicion && actionEvidence && !negativeEvidence &&
      (tempPath || (startup && startupPath) || repeatedUnsignedService)) {
    return verdict(0.96,
      scheduled && !service && !startup
        ? PATTERNS[1].name : PATTERNS[0].name);
  }

  // Suspicious but uncorroborated persistence signals merit a review.
  if (tagged && level >= 5)
    return verdict(0.65, PATTERNS[2].name);

  return verdict(0.08, 'no_matching_pattern');
}
