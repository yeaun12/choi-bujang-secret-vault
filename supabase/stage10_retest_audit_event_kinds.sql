-- Stage 10 retest outcome event kinds; preserves all existing audit entries
-- and existing privileges/RLS. No backup or note content is copied or changed.
ALTER TABLE public.stage10_restore_audit
  DROP CONSTRAINT stage10_restore_audit_event_kind_check,
  ADD CONSTRAINT stage10_restore_audit_event_kind_check
  CHECK (event_kind IN (
    'backup_created', 'backup_rejected',
    'restore_requested', 'restore_rejected', 'restore_applied',
    'restore_verified', 'restore_failed',
    'retest_passed', 'retest_failed', 'retest_skipped'
  ));
