// Stage 9, task 1: accept only the verified local practice event contract.
// The contract provides timestamp, HTTP method, and pseudonymous identity.sub.
// It does NOT provide a verified device, network, or decision field.
// No event bodies, tokens, names, or unknown fields are retained or logged.
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  return events.map((event) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)
        || typeof event.at !== 'string' || !UTC_ISO.test(event.at)
        || !Number.isFinite(Date.parse(event.at))
        || typeof event.method !== 'string' || !METHODS.has(event.method)
        || !event.identity || typeof event.identity !== 'object'
        || Array.isArray(event.identity)
        || typeof event.identity.sub !== 'string'
        || !event.identity.sub.trim() || event.identity.sub.length > 256) {
      throw new TypeError('invalid_detection_event');
    }

    // Allowlist extraction: output cannot contain unknown event metadata.
    return {
      atMs: Date.parse(event.at),
      method: event.method,
      subject: event.identity.sub,
    };
  });
}

// Stage 9, task 2: local practice detection of unusually frequent reads.
// A strict sliding 10-minute window is evaluated separately for each verified
// pseudonymous subject. Device and network signals are NOT present in the
// practice event contract, so this function returns a CANDIDATE, not proof
// of the compound network + burst anomaly described by the stage card.
const TEN_MINUTES_MS = 10 * 60 * 1000;
const BURST_THRESHOLD = 120;

export function findReadBurstCandidate(events) {
  const reads = readDetectionEvents(events)
    .filter(event => event.method === 'GET')
    .sort((a, b) => a.atMs - b.atMs || a.subject.localeCompare(b.subject));

  const bySubject = new Map();
  for (const event of reads) {
    let history = bySubject.get(event.subject);
    if (!history) {
      history = { times: [], first: 0 };
      bySubject.set(event.subject, history);
    }

    history.times.push(event.atMs);
    while (event.atMs - history.times[history.first] >= TEN_MINUTES_MS) {
      history.first++;
    }

    // Exactly 120 GETs is normal for this LOCAL contract. 121 is anomalous.
    if (history.times.length - history.first > BURST_THRESHOLD) {
      return { subject: event.subject, reasonCode: 'burst_read' };
    }
  }
  return null;
}

export function detect(events) {
  // Stage 3 will define the separate decision/proposal result. Until then,
  // detecting a burst candidate never revokes a device or changes access.
  findReadBurstCandidate(events);
  return { action: 'observe' };
}
