-- Stage 10 / task 3 preparation: private, pre-incident judge-B note snapshots
-- and append-only metadata-only recovery audit. No existing rows are read,
-- copied, updated or deleted by this migration.
--
-- Only the server may write a backup after validating a signed judge identity
-- with aleph_identity = 'b', a matching run_id and derived owner_id.
-- A SHA-256 digest detects changed bytes; it does not prove a snapshot predates
-- an attack. Capture time and source must be verified by the API/official judge.
-- This migration intentionally creates NO backup rows or recovery endpoint.

CREATE TABLE public.stage10_note_backups (
  judge_run_id uuid NOT NULL,
  identity_label text NOT NULL DEFAULT 'b'
    CHECK (identity_label = 'b'),
  note_id uuid NOT NULL,
  owner_id uuid NOT NULL,
  title text NOT NULL,
  content text NOT NULL,
  note_created_at timestamptz NOT NULL,
  content_sha256 text NOT NULL
    CHECK (content_sha256 ~ '^[0-9a-f]{64}$')
    CHECK (content_sha256 = encode(sha256(convert_to(content, 'UTF8')), 'hex')),
  captured_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (judge_run_id, note_id)
);

-- No FK on note_id: a deleted source row MUST NOT delete its backup.
CREATE INDEX stage10_note_backups_owner_lookup
  ON public.stage10_note_backups (judge_run_id, owner_id, note_id);

CREATE TABLE public.stage10_restore_audit (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  judge_run_id uuid,
  identity_label text CHECK (identity_label IS NULL OR identity_label = 'b'),
  note_id uuid,
  owner_id uuid,
  event_kind text NOT NULL CHECK (event_kind IN (
    'backup_created', 'backup_rejected',
    'restore_requested', 'restore_rejected',
    'restore_applied', 'restore_verified', 'restore_failed'
  )),
  reason_code text NOT NULL
    CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  content_sha256 text
    CHECK (content_sha256 IS NULL OR content_sha256 ~ '^[0-9a-f]{64}$')
);

-- Deny client access even if the browser knows table names.
ALTER TABLE public.stage10_note_backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stage10_restore_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.stage10_note_backups, public.stage10_restore_audit
  FROM PUBLIC, anon, authenticated, service_role;

-- Only authenticated SERVER-SIDE operations using service_role may
-- insert/read these rows; never grant UPDATE/DELETE (immutable backups/audit).
GRANT SELECT, INSERT ON TABLE public.stage10_note_backups TO service_role;
GRANT SELECT, INSERT ON TABLE public.stage10_restore_audit TO service_role;

COMMENT ON TABLE public.stage10_note_backups IS
  'Private immutable pre-incident B-only snapshots; do not backfill from current notes.';
COMMENT ON TABLE public.stage10_restore_audit IS
  'Append-only restore metadata; no note contents, authorization tokens or private keys.';
