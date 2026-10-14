// Stage 12 / task 1. Present only observed server metadata and explicitly unknown states.
// Never read note bodies, account identifiers, tokens, WebAuthn keys or raw events.
import { randomUUID } from 'node:crypto';
import { RULE_IDS } from './decider.mjs';

const knownAuditKinds = new Set([
  'backup_created', 'backup_rejected', 'restore_requested', 'restore_rejected',
  'restore_applied', 'restore_verified', 'restore_failed',
]);

function validCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function validTimestamp(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return null;
  return new Date(value).toISOString();
}

// A successful empty DB query is distinct from an unexecuted test or a failed query.
export function summarizeWarRoomEvidence({ backups, audits, requestId, observedAt }) {
  const backupCount = backups?.error ? null : validCount(backups?.count);
  const auditCount = audits?.error ? null : validCount(audits?.count);
  const available = backupCount !== null && auditCount !== null;
  const latestBackupVersion = available && backupCount > 0
    ? validTimestamp(backups.data?.[0]?.captured_at) : null;
  const latestAuditAt = available && auditCount > 0
    ? validTimestamp(audits.data?.[0]?.occurred_at) : null;
  const rawKind = available && auditCount > 0 ? audits.data?.[0]?.event_kind : null;
  const latestAuditKind = knownAuditKinds.has(rawKind) ? rawKind : null;
  const complete = available &&
    (backupCount === 0 || latestBackupVersion !== null) &&
    (auditCount === 0 || (latestAuditAt !== null && latestAuditKind !== null));
  const restoreStatus = !complete ? 'unavailable'
    : backupCount + auditCount === 0 ? 'checked_empty' : 'observed';
  return {
    schema: 'aleph.stage12.war_room.v1',
    requestId, observedAt,
    policy: {
      status: 'configured_not_tested',
      source: 'src/decider.mjs',
      ruleIds: [...RULE_IDS],
      ruleCount: RULE_IDS.length,
    },
    detection: {
      status: 'not_executed',
      source: 'no_verified_operational_detection_feed',
      eventCount: null,
    },
    revocation: {
      status: 'not_executed',
      source: 'no_verified_revocation_execution_feed',
      completedCount: null,
    },
    recovery: {
      status: restoreStatus,
      source: 'server_side_backup_and_audit_tables',
      backupCount: complete ? backupCount : null,
      latestBackupVersion: complete ? latestBackupVersion : null,
      auditCount: complete ? auditCount : null,
      latestAuditKind: complete ? latestAuditKind : null,
      latestAuditAt: complete ? latestAuditAt : null,
    },
  };
}

export async function collectWarRoomEvidence(db, { now = () => new Date().toISOString(),
  newRequestId = randomUUID } = {}) {
  // Only aggregate counts and the most recent timestamps/event-kind leave the server.
  const [backups, audits] = await Promise.all([
    db.from('stage10_note_backups')
      .select('captured_at', { count: 'exact' })
      .order('captured_at', { ascending: false }).limit(1),
    db.from('stage10_restore_audit')
      .select('occurred_at, event_kind', { count: 'exact' })
      .order('occurred_at', { ascending: false }).limit(1),
  ]);
  return summarizeWarRoomEvidence({
    backups, audits, requestId: newRequestId(), observedAt: now(),
  });
}

export function redactWarRoomLog(result) {
  return {
    event: 's12_war_room_snapshot',
    requestId: result.requestId,
    observedAt: result.observedAt,
    policyRuleCount: result.policy.ruleCount,
    detectionStatus: result.detection.status,
    revocationStatus: result.revocation.status,
    recoveryStatus: result.recovery.status,
    backupCount: result.recovery.backupCount,
    auditCount: result.recovery.auditCount,
  };
}
