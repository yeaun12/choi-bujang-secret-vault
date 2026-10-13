-- Real PostgreSQL storage verification, NOT an official judge/API test.
-- Execute the ENTIRE file in one call. All fixtures are rolled back.
-- Existing rows are never updated/deleted. No policy/schema changes.
BEGIN;
SET LOCAL ROLE service_role;
DO $check$
DECLARE
  run_id uuid := gen_random_uuid();
  b_owner uuid := gen_random_uuid();
  a_owner uuid := gen_random_uuid();
  target uuid := gen_random_uuid();
  untouched uuid := gen_random_uuid();
  source_row public.notes%ROWTYPE;
  saved public.stage10_note_backups%ROWTYPE;
  saved_again public.stage10_note_backups%ROWTYPE;
  recovered public.notes%ROWTYPE;
  old_notes bigint;
  old_backups bigint;
  old_audits bigint;
BEGIN
  SELECT count(*) INTO old_notes FROM public.notes;
  SELECT count(*) INTO old_backups FROM public.stage10_note_backups;
  SELECT count(*) INTO old_audits FROM public.stage10_restore_audit;
  IF has_table_privilege(current_user, 'public.stage10_note_backups', 'UPDATE')
     OR has_table_privilege(current_user, 'public.stage10_restore_audit', 'DELETE') THEN
    RAISE EXCEPTION 'stage10_immutable_storage_privileges_failed';
  END IF;
  INSERT INTO public.notes(id,owner_id,title,content)
    VALUES(target,b_owner,'synthetic B','synthetic original B content'),
          (untouched,a_owner,'synthetic A','synthetic A content');
  SELECT * INTO STRICT source_row FROM public.notes WHERE id=target AND owner_id=b_owner;
  INSERT INTO public.stage10_note_backups
    (judge_run_id,identity_label,note_id,owner_id,title,content,note_created_at,content_sha256)
    VALUES(run_id,'b',source_row.id,source_row.owner_id,source_row.title,source_row.content,
      source_row.created_at,encode(sha256(convert_to(source_row.content,'UTF8')),'hex'));
  SELECT * INTO STRICT saved FROM public.stage10_note_backups
    WHERE judge_run_id=run_id AND identity_label='b' AND note_id=target AND owner_id=b_owner;
  IF saved.content_sha256 <> encode(sha256(convert_to(saved.content,'UTF8')),'hex')
     OR saved.note_id <> source_row.id OR saved.owner_id <> source_row.owner_id
     OR saved.captured_at < saved.note_created_at THEN
    RAISE EXCEPTION 'stage10_backup_readback_failed';
  END IF;
  INSERT INTO public.stage10_restore_audit
    (judge_run_id,identity_label,note_id,owner_id,event_kind,reason_code,content_sha256)
    VALUES(run_id,'b',target,b_owner,'backup_created','sql_fixture_readback',saved.content_sha256);
  UPDATE public.notes SET title='synthetic altered',content='synthetic corrupted'
    WHERE id=target AND owner_id=b_owner;
  SELECT * INTO STRICT saved_again FROM public.stage10_note_backups
    WHERE judge_run_id=run_id AND identity_label='b' AND note_id=target AND owner_id=b_owner;
  IF saved_again IS DISTINCT FROM saved THEN
    RAISE EXCEPTION 'stage10_backup_changed_before_write';
  END IF;
  UPDATE public.notes SET title=saved_again.title,content=saved_again.content,
    created_at=saved_again.note_created_at WHERE id=target AND owner_id=b_owner;
  SELECT * INTO STRICT recovered FROM public.notes WHERE id=target;
  IF recovered.id <> saved.note_id OR recovered.owner_id <> saved.owner_id
     OR encode(sha256(convert_to(recovered.content,'UTF8')),'hex') <> saved.content_sha256 THEN
    RAISE EXCEPTION 'stage10_tampered_restore_mismatch';
  END IF;
  -- Deleted-row recovery retains the identical tuple.
  DELETE FROM public.notes WHERE id=target AND owner_id=b_owner;
  INSERT INTO public.notes(id,owner_id,title,content,created_at)
    VALUES(saved.note_id,saved.owner_id,saved.title,saved.content,saved.note_created_at);
  SELECT * INTO STRICT recovered FROM public.notes WHERE id=target AND owner_id=b_owner;
  IF recovered.id <> saved.note_id OR recovered.owner_id <> saved.owner_id
     OR encode(sha256(convert_to(recovered.content,'UTF8')),'hex') <> saved.content_sha256 THEN
    RAISE EXCEPTION 'stage10_deleted_restore_mismatch';
  END IF;
  -- These are storage-scope checks, not HTTP 200/404 claims.
  IF NOT EXISTS(SELECT 1 FROM public.notes WHERE id=target AND owner_id=b_owner)
     OR EXISTS(SELECT 1 FROM public.notes WHERE id=untouched AND owner_id=b_owner)
     OR NOT EXISTS(SELECT 1 FROM public.notes WHERE id=untouched AND owner_id=a_owner
       AND content='synthetic A content') THEN
    RAISE EXCEPTION 'stage10_storage_scope_failed';
  END IF;
  IF (SELECT count(*) FROM public.notes) <> old_notes+2
     OR (SELECT count(*) FROM public.stage10_note_backups) <> old_backups+1
     OR (SELECT count(*) FROM public.stage10_restore_audit) <> old_audits+1 THEN
    RAISE EXCEPTION 'stage10_fixture_scope_or_audit_failed';
  END IF;
END
$check$;
ROLLBACK;
