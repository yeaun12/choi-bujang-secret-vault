-- 8단계에서 Supabase에 적용한 비파괴적 DDL (재현 기록)
-- Existing public.notes table and user data are not changed.
CREATE TABLE IF NOT EXISTS public.instructor_memberships (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  granted_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.instructor_notices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_by uuid NOT NULL REFERENCES auth.users(id),
  title text NOT NULL,
  content text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.instructor_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.instructor_notices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.instructor_memberships, public.instructor_notices
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.instructor_memberships, public.instructor_notices
  FROM service_role;
GRANT SELECT ON TABLE public.instructor_memberships TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.instructor_notices TO service_role;

-- No role membership is created here. Instructor promotion needs separate approval.
-- The server verifies the JWT and re-checks membership on every notice write.
