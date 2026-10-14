// XDR-05: classify one synthetic privilege-escalation alert at a time.
// Import-free, stateless and offline; returns decisions, never executes blocks.
const PATTERNS = Object.freeze({
  group: 'unexpected_administrator_group_change',
  recent: 'recent_privilege_gain_and_command',
  command: 'unusual_privileged_command',
  session: 'unusual_privileged_session_change',
  review: 'privilege_context_needs_review',
  none: 'no_matching_pattern',
});

const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const str = value => typeof value === 'string' ? value.slice(0, 4096).trim() : '';
const num = value => {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const decision = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});

function hasPrivilegeTag(rule) {
  const mitre = rule.mitre;
  const ids = Array.isArray(mitre) ? mitre
    : Array.isArray(mitre?.id) ? mitre.id
    : typeof mitre?.id === 'string' ? [mitre.id]
    : typeof mitre === 'string' ? [mitre] : [];
  return ids.some(id => /^T(?:1068|1078)(?:\.\d{3})?$/i.test(String(id)));
}
function hasSource(data, alert) {
  const ip = str(data.srcip || data.src_ip || data.source_ip || alert.srcip || alert.source?.ip);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))
    return ip.split('.').every(part => Number(part) <= 255);
  return ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return decision(0.05, PATTERNS.none);
  const rule = object(alert.rule);
  const data = object(alert.data);
  const text = str(rule.description || alert.description).toLowerCase();
  const level = num(rule.level ?? alert.ruleLevel) ?? 0;
  const count = num(data.count ?? data.eventCount);
  const privilegedGroup = /^(?:administrators|administrator|sudo|wheel|admin)$/i.test(str(data.group));
  const tagged = hasPrivilegeTag(rule);
  const source = hasSource(data, alert);
  const user = str(data.srcuser || data.sourceUser || alert.user);
  const actionFailedOrDenied = /취소|실패|변경은\s*없|변경\s*없|읽기만|조회만|그룹은\s*아닙|not\s+admin|cancelled|failed|denied|read[\s-]*only/i.test(text);
  const normalContext = /평소 주소|평소.*그대로|정상적인\s*관리|승인된\s*관리|authorized\s+admin/i.test(text);

  // Administrator group membership is not itself malicious. Require a
  // confirmed change and an unusual context in the *same* alert.
  const groupChanged = privilegedGroup && (
    /관리자\s*그룹.*(?:추가|들어가|들어왔)/i.test(text) ||
    /관리자\s*그룹\s*추가/i.test(text) ||
    /다시\s*관리자로\s*들어왔/i.test(text) ||
    /added\s+to\s+(?:the\s+)?administrators/i.test(text)
  );
  const suspiciousGroupContext = /원격 주소|평범한 계정|곧바로|업무처럼\s*보이지\s*않는|명령\s*실행.*같이|빠진\s*계정.*다시|1분\s*뒤|unusual|unexpected|unapproved/i.test(text);
  const manyChanged = count !== null && count >= 4 &&
    /계정\s*\d+개.*관리자\s*그룹/i.test(text);
  const groupAttack = groupChanged && (suspiciousGroupContext || manyChanged);

  const privilegedCommand = /관리자\s*명령|권한\s*명령|admin(?:istrator)?\s+command|privileged\s+command/i.test(text);
  const commandExecuted = /실행|executed|ran/i.test(text);
  const recentlyElevated = /방금\s*관리자가\s*된|곧바로\s*권한|newly\s+elevated/i.test(text);
  const unusualCommand = /수업\s*시간\s*밖|처음\s*보는\s*주소|다른\s*계정의\s*권한|업무\s*시간\s*외|outside\s+(?:normal|business)\s+hours|unfamiliar\s+source/i.test(text);
  const unusualSession = /세션.*관리자\s*권한으로\s*바뀌|session.*(?:administrator|admin).*elevat/i.test(text) &&
    /처음\s*봅|처음\s*보는|낯선|unfamiliar|unknown/i.test(text);

  // MITRE tagging or a high rule level cannot justify blocking by itself.
  if (tagged && source && user && level >= 10 && !actionFailedOrDenied && !normalContext) {
    if (groupAttack) return decision(0.97, PATTERNS.group);
    if (unusualSession) return decision(0.96, PATTERNS.session);
    if (privilegedCommand && commandExecuted && recentlyElevated)
      return decision(0.96, PATTERNS.recent);
    if (privilegedCommand && commandExecuted && unusualCommand)
      return decision(0.96, PATTERNS.command);
  }

  // Any uncertain privilege-related alert must be investigated, not blocked.
  if (tagged && level >= 5) return decision(0.65, PATTERNS.review);
  return decision(0.08, PATTERNS.none);
}
