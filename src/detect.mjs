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

export function detect(events) {
  // Input handling only. Detection rules and revocation proposals follow in tasks 2/3.
  readDetectionEvents(events);
  return { action: 'observe' };
}
