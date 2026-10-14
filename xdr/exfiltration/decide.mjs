// XDR-06: classify one synthetic data-exfiltration alert at a time.
// Import-free, stateless, offline. "block" is a decision, not a live firewall action.
const PATTERN_DEFINITIONS = Object.freeze([
  {
    "name": "unexpected_bulk_data_transfer",
    "technique": "T1048/T1041",
    "condition": "T1041/T1048 tag, confirmed high-volume outbound transfer to a new external IP plus many files, or evidence of an entire vault copied externally.",
    "rationale": "High-volume outbound transfer to an unfamiliar destination with many files, or confirmed copy of whole vault to an external address."
  },
  {
    "name": "correlated_repeated_large_transfer",
    "technique": "T1041/T1048",
    "condition": "T1041/T1048 tag, large verified outbound volume and per-alert correlated repeat count, with unusual hours or clear repeated bulk transfers.",
    "rationale": "Large outbound volume and verified repeated transfers, or repetition outside usual hours."
  },
  {
    "name": "unusual_outbound_transfer_channel",
    "technique": "T1041/T1048",
    "condition": "T1041/T1048 tag, unusual outbound port with many repeated file transfers, or command channel and new destination with confirmed repeat count.",
    "rationale": "Large transfers using an unusual port and repeated many-file activity, or command channel transfer with novel destination and repeated count."
  },
  {
    "name": "suspicious_archive_outbound_transfer",
    "technique": "T1048",
    "condition": "T1048 tag, large archive transfer to unfamiliar external IP, corroborated by off-hours timing, repetition or multiple destinations.",
    "rationale": "Large archive/bundled-data transfer to a novel destination with further corroboration from out-of-hours, repeated, or multi-destination activity."
  },
  {
    "name": "exfiltration_context_needs_review",
    "technique": "T1041/T1048",
    "condition": "T1041/T1048 tag with an isolated or incomplete outbound signal; do not block without confirmed volume and abnormal context.",
    "rationale": "Incomplete, isolated or lower-severity outbound activity; do not enforce a block."
  }
]);

const PATTERNS = Object.freeze({
  mass: 'unexpected_bulk_data_transfer',
  repeated: 'correlated_repeated_large_transfer',
  channel: 'unusual_outbound_transfer_channel',
  archive: 'suspicious_archive_outbound_transfer',
  review: 'exfiltration_context_needs_review',
  none: 'no_matching_pattern',
});

const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const str = value => typeof value === 'string' ? value.slice(0, 4096).trim() : '';
const quantity = value => {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  const s = String(value).trim();
  if (!/^\d+(?:\.\d+)?$/.test(s)) return null;
  const n = Number(s);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
};
const verdict = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});

function mitreExfil(rule) {
  const mitre = rule.mitre;
  const ids = Array.isArray(mitre) ? mitre
    : Array.isArray(mitre?.id) ? mitre.id
    : typeof mitre?.id === 'string' ? [mitre.id]
    : typeof mitre === 'string' ? [mitre] : [];
  return ids.some(id => /^T(?:1041|1048)(?:\.\d{3})?$/i.test(String(id)));
}

function address(value) {
  const ip = str(value);
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip))
    return ip.split('.').every(part => Number(part) <= 255) ? ip : '';
  return ip.includes(':') && /^[0-9a-f:.]+$/i.test(ip) ? ip : '';
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return verdict(0.05, PATTERNS.none);
  const data = obj(alert.data);
  const rule = obj(alert.rule);
  const desc = str(rule.description || alert.description).toLowerCase();
  const level = quantity(rule.level ?? alert.ruleLevel) ?? 0;
  const bytes = quantity(data.bytes ?? data.bytesSent ?? data.outboundBytes);
  const files = quantity(data.files ?? data.fileCount);
  const count = quantity(data.count ?? data.transferCount);
  const src = address(data.srcip || data.src_ip || alert.srcip || alert.source?.ip);
  const dst = address(data.dstip || data.dst_ip || data.destination_ip || alert.dstip || alert.destination?.ip);
  const user = str(data.srcuser || data.sourceUser || alert.user);
  const tagged = mitreExfil(rule);

  const sent = /나갔|전송|복사됐|올라갔|(?:sent|transferred|uploaded|copied)\b/i.test(desc);
  const notSent = /외부\s*전송은\s*아직\s*없|전송(?:은|이)?\s*없|전송.*실패|복사.*실패|not\s+(?:transferred|sent)|transfer\s+failed/i.test(desc);
  const normalContext = /승인된\s*백업|정상적인\s*대용량\s*백업|authorized\s+(?:backup|transfer)|approved\s+(?:backup|transfer)/i.test(desc);
  const novel = /처음\s*보는\s*(?:목적지|주소)|낯선\s*목적지|new\s+(?:destination|address)|unknown\s+destination/i.test(desc);
  const offHours = /수업\s*시간\s*밖|업무\s*시간\s*밖|근무\s*시간\s*밖|outside\s+(?:business|working)\s+hours/i.test(desc);
  const repeated = /반복|연속|\d+\s*번|짧은\s*시간|repeated|consecutive/i.test(desc);
  const archive = /압축\s*파일|메모\s*묶음|archive|compressed/i.test(desc);
  const manyFiles = files !== null && files >= 30 && /자료|파일|메모|document|files?/i.test(desc);
  const correlated = count !== null && count >= 5 && repeated;
  const largeRepeated = correlated && /대용량|큰\s*파일|large|bulk/i.test(desc);
  const unusualPort = /평소에\s*쓰지\s*않던\s*포트|비표준\s*포트|unusual\s+port|nonstandard\s+port/i.test(desc);
  const commandChannel = /명령\s*통로|command\s+channel|c2\s+channel/i.test(desc);
  const fullVault = /자료실\s*전체|전체.*복사|entire\s+(?:vault|dataset)/i.test(desc);
  const external = /외부\s*주소|external\s+(?:address|destination)/i.test(desc);
  const multipleDestinations = /목적지\s*두\s*곳|두\s*곳으로|multiple\s+destinations/i.test(desc);

  // A large transfer is not automatically exfiltration. The same alert must
  // contain a real outbound destination, high severity, technique evidence,
  // and more than one corroborating abnormality.
  if (tagged && level >= 10 && src && dst && src !== dst && user &&
      bytes !== null && bytes >= 50_000_000 && sent && !notSent && !normalContext) {
    if (novel && manyFiles) return verdict(0.97, PATTERNS.mass);
    if (novel && archive && (offHours || repeated || multipleDestinations))
      return verdict(0.96, PATTERNS.archive);
    if (largeRepeated || (offHours && correlated))
      return verdict(0.96, PATTERNS.repeated);
    if (unusualPort && repeated && manyFiles)
      return verdict(0.96, PATTERNS.channel);
    if (fullVault && external && manyFiles)
      return verdict(0.97, PATTERNS.mass);
    if (commandChannel && novel && correlated)
      return verdict(0.96, PATTERNS.channel);
  }

  // Partial or low-volume indications require human review rather than a block.
  if (tagged && level >= 5)
    return verdict(0.65, PATTERNS.review);
  return verdict(0.08, PATTERNS.none);
}
