// XDR-03: independent classification of one training alert at a time.
// No imports, I/O, network, environment access or cross-alert state.
const PATTERNS = Object.freeze([
  { name: 'log4shell_remote_jndi_lookup', technique: 'T1190' },
  { name: 'cve_context_needs_review', technique: 'T1190' },
]);

const object = (value) => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const number = (value) => {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : null;
};
const string = (value) => typeof value === 'string' ? value.slice(0, 4096) : '';
const result = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence,
  reason,
});

function isT1190(rule) {
  const m = rule.mitre;
  const ids = Array.isArray(m) ? m
    : Array.isArray(m?.id) ? m.id
    : typeof m?.id === 'string' ? [m.id]
    : typeof m === 'string' ? [m] : [];
  return ids.some(id => /^T1190(?:\.\d{3})?$/i.test(String(id)));
}

function validSource(data, alert) {
  const ip = string(data.srcip || data.src_ip || data.source_ip || alert.srcip || alert.source?.ip).trim();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))
    return ip.split('.').every(part => Number(part) <= 255);
  return ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip);
}

function hasRemoteLookup(data) {
  const headers = object(data.headers);
  const values = [data.url, data.uri, data.request, data.useragent, data.userAgent,
    data.payload, data.query, headers['user-agent'], headers.userAgent];
  // Decode a bounded number of times to handle URL-encoded signatures.
  return values.some(value => {
    let candidate = string(value);
    for (let i = 0; i < 2; i++) {
      try {
        const next = decodeURIComponent(candidate);
        if (next === candidate) break;
        candidate = next;
      } catch { break; }
    }
    return /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:\/\/[^}\s]{3,}\}/i.test(candidate);
  });
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return result(0.05, 'no_matching_pattern');

  const rule = object(alert.rule);
  const data = object(alert.data);
  const level = number(rule.level ?? alert.ruleLevel) ?? 0;
  const tagged = isT1190(rule);
  const source = validSource(data, alert);
  const lookup = hasRemoteLookup(data);

  // A complete remote lookup in request data is evidence; a CVE name in
  // a search query or narrative alone is not evidence of exploitation.
  if (lookup && source && ((tagged && level >= 9) || level >= 12))
    return result(0.97, PATTERNS[0].name);

  if (lookup || (tagged && level >= 5))
    return result(0.65, PATTERNS[1].name);

  return result(0.08, 'no_matching_pattern');
}
