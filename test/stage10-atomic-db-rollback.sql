-- Stage 10: independent PostgreSQL integration test AFTER applying
-- db/stage10-atomic-b-creation.sql. Does not retain synthetic data.
-- Run as a privileged database operator in a reviewed TEST database.
BEGIN;

DO $verify$
DECLARE
  run_id uuid := gen_random_uuid();
  expected_owner uuid := gen_random_uuid();
  requested_id uuid := gen_random_uuid();
  created_id uuid;
  expected_hash text := encode(sha256(convert_to('stage10 synthetic atomic restore test', 'UTF8')), 'hex');
  found_backup public.stage10_note_backups%ROWTYPE;
  note_count integer;
  backup_count integer;
  audit_count integer;
BEGIN
  IF to_regprocedure('public.stage10_create_b_note(uuid,uuid,text,text,uuid)') IS NULL THEN
    RAISE EXCEPTION 'stage10_atomic_rpc_not_installed';
  END IF;

  SELECT x.note_id INTO created_id
  FROM public.stage10_create_b_note(run_id, expected_owner,
    'stage10 synthetic atomic test', 'stage10 synthetic atomic restore test',
    requested_id) AS x;

  IF created_id IS DISTINCT FROM requested_id THEN
    RAISE EXCEPTION 'stage10_created_id_mismatch';
  END IF;

  SELECT * INTO found_backup FROM public.stage10_note_backups AS b
  WHERE b.judge_run_id = run_id AND b.note_id = requested_id
    AND b.owner_id = expected_owner AND b.identity_label = 'b';
  IF NOT FOUND OR found_backup.content_sha256 IS DISTINCT FROM expected_hash
    OR found_backup.content_sha256 IS DISTINCT FROM
      encode(sha256(convert_to(found_backup.content, 'UTF8')), 'hex') THEN
    RAISE EXCEPTION 'stage10_backup_digest_mismatch';
  END IF;

  SELECT count(*) INTO note_count FROM public.notes WHERE id = requested_id;
  SELECT count(*) INTO backup_count FROM public.stage10_note_backups
  WHERE judge_run_id = run_id AND note_id = requested_id;
  SELECT count(*) INTO audit_count FROM public.stage10_restore_audit
  WHERE judge_run_id = run_id AND note_id = requested_id
    AND event_kind = 'backup_created' AND reason_code = 'initial_created_note';
  IF note_count <> 1 OR backup_count <> 1 OR audit_count <> 1 THEN
    RAISE EXCEPTION 'stage10_atomic_creation_incomplete';
  END IF;

  BEGIN
    PERFORM * FROM public.stage10_create_b_note(run_id, expected_owner,
      'stage10 synthetic duplicate', 'never overwrite', requested_id);
    RAISE EXCEPTION 'stage10_duplicate_accepted';
  EXCEPTION
    WHEN unique_violation THEN NULL;
  END;

  SELECT count(*) INTO note_count FROM public.notes
  WHERE id = requested_id AND content = 'stage10 synthetic atomic restore test';
  IF note_count <> 1 THEN
    RAISE EXCEPTION 'stage10_duplicate_altered_existing_note';
  END IF;

  IF has_function_privilege('anon',
    'public.stage10_create_b_note(uuid,uuid,text,text,uuid)', 'EXECUTE')
    OR has_function_privilege('authenticated',
    'public.stage10_create_b_note(uuid,uuid,text,text,uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'stage10_atomic_rpc_publicly_executable';
  END IF;
END;
$verify$;

-- Every synthetic row and audit event above is rolled back.
ROLLBACK;
