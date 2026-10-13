-- Stage 10 / TEST-ONLY MIGRATION PROPOSAL
-- NOT APPLIED TO PRODUCTION. Review and verify before running.
-- The signed judge-B identity must be verified by the server first.
--
-- One PostgreSQL transaction creates the note, immutable pre-incident
-- snapshot and append-only audit event. A failure rolls back all writes.
-- Only service_role can invoke this function (never anon/authenticated).
CREATE OR REPLACE FUNCTION public.stage10_create_b_note(
  p_judge_run_id uuid,
  p_owner_id uuid,
  p_title text,
  p_content text,
  p_note_id uuid DEFAULT NULL
)
RETURNS TABLE(note_id uuid, owner_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  saved public.notes%ROWTYPE;
  verified public.stage10_note_backups%ROWTYPE;
  digest text;
BEGIN
  IF p_judge_run_id IS NULL OR p_owner_id IS NULL
     OR p_title IS NULL OR p_content IS NULL THEN
    RAISE EXCEPTION 'stage10_invalid_creation_input' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.notes (id, owner_id, title, content)
  VALUES (coalesce(p_note_id, gen_random_uuid()), p_owner_id, p_title, p_content)
  RETURNING * INTO saved;

  digest := encode(sha256(convert_to(saved.content, 'UTF8')), 'hex');
  INSERT INTO public.stage10_note_backups (
    judge_run_id, identity_label, note_id, owner_id,
    title, content, note_created_at, content_sha256
  ) VALUES (
    p_judge_run_id, 'b', saved.id, saved.owner_id,
    saved.title, saved.content, saved.created_at, digest
  );

  SELECT * INTO verified
  FROM public.stage10_note_backups AS b
  WHERE b.judge_run_id = p_judge_run_id AND b.identity_label = 'b'
    AND b.note_id = saved.id AND b.owner_id = saved.owner_id;

  IF NOT FOUND OR verified.content_sha256 <> digest
     OR verified.title IS DISTINCT FROM saved.title
     OR verified.content IS DISTINCT FROM saved.content
     OR verified.note_created_at IS DISTINCT FROM saved.created_at THEN
    RAISE EXCEPTION 'stage10_backup_readback_failed' USING ERRCODE = 'P0001';
  END IF;

  INSERT INTO public.stage10_restore_audit (
    judge_run_id, identity_label, note_id, owner_id,
    event_kind, reason_code, content_sha256
  ) VALUES (
    p_judge_run_id, 'b', saved.id, saved.owner_id,
    'backup_created', 'initial_created_note', digest
  );

  note_id := saved.id;
  owner_id := saved.owner_id;
  RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.stage10_create_b_note(uuid, uuid, text, text, uuid)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.stage10_create_b_note(uuid, uuid, text, text, uuid)
  TO service_role;

-- Warning: a privileged function owner must be trusted. This proposal has
-- no authorization for end-user invocations; server verifies official B JWT
-- and supplies a run-bound owner ID before using its service-role client.
