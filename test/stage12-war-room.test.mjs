import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeWarRoomEvidence, redactWarRoomLog } from '../src/stage12-war-room.mjs';
import { protectedPath } from '../src/stage11-device-proof.mjs';

const base = {
  requestId: '8daed994-8fe1-4295-a68a-303159882425',
  observedAt: '2026-10-14T00:00:00.000Z',
};

test('configured rules are not misrepresented as real access decisions', () => {
  const report = summarizeWarRoomEvidence({ ...base,
    backups: { count: 0, data: [], error: null },
    audits: { count: 0, data: [], error: null },
  });
  assert.equal(report.policy.ruleCount, 3);
  assert.equal(report.policy.status, 'configured_not_tested');
  assert.equal(report.recovery.status, 'checked_empty');
  assert.equal(report.recovery.backupCount, 0);
  assert.equal(report.recovery.auditCount, 0);
  assert.equal(report.detection.status, 'not_executed');
  assert.equal(report.detection.eventCount, null);
  assert.equal(report.revocation.completedCount, null);
});

test('restore version and redacted logs follow real count, time, and kind', () => {
  const report = summarizeWarRoomEvidence({ ...base,
    backups: { count: 2, data: [{ captured_at: '2026-10-14T01:00:00+00:00',
      title: 'DO NOT LEAK NOTE', content: 'DO NOT LEAK NOTE BODY',
      owner_id: 'secret-owner' }], error: null },
    audits: { count: 7, data: [{ occurred_at: '2026-10-14T01:30:00Z',
      event_kind: 'restore_verified', content_sha256: 'secret-hash' }], error: null },
  });
  assert.equal(report.recovery.status, 'observed');
  assert.equal(report.recovery.backupCount, 2);
  assert.equal(report.recovery.latestBackupVersion, '2026-10-14T01:00:00.000Z');
  assert.equal(report.recovery.latestAuditKind, 'restore_verified');
  const logs = redactWarRoomLog(report);
  assert.equal(logs.backupCount, report.recovery.backupCount);
  assert.equal(logs.auditCount, report.recovery.auditCount);
  assert.equal(logs.latestBackupVersion, report.recovery.latestBackupVersion);
  assert.equal(logs.latestAuditAt, report.recovery.latestAuditAt);
  assert.equal(logs.latestAuditKind, report.recovery.latestAuditKind);
  assert.equal(logs.requestId, report.requestId);
  assert.doesNotMatch(JSON.stringify({ report, logs }), /DO NOT LEAK|secret-owner|secret-hash/);
});

test('failed, malformed or unverifiable DB evidence never reports success', () => {
  const report = summarizeWarRoomEvidence({ ...base,
    backups: { count: null, data: null, error: { message: 'private' } },
    audits: { count: 4, data: [{ event_kind: 'restore_verified' }], error: null },
  });
  assert.equal(report.recovery.status, 'unavailable');
  assert.equal(report.recovery.backupCount, null);
  assert.equal(report.recovery.auditCount, null);
});

test('operational dashboard is only available through a signed GET proof path', () => {
  assert.equal(protectedPath('GET', '/api/war-room'), true);
  assert.equal(protectedPath('POST', '/api/war-room'), false);
  assert.equal(protectedPath('GET', '/api/war-room?debug=1'), false);
  assert.equal(protectedPath('GET', '/api/other'), false);
});
