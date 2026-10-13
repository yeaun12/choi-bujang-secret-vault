// Server-side instructor permissions: only a validated login subject and DB membership count.
export const NOTICE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export function noticePath(request) {
  try {
    const url = new URL(request.url);
    if (url.search || url.hash) return null;
    const pathname = url.pathname;
    if (pathname === '/api/instructor-notices') return { collection: true };
    const match = /^\/api\/instructor-notices\/([0-9a-f-]{36})$/iu.exec(pathname);
    if (!match || !NOTICE_UUID.test(match[1])) return null;
    return { collection: false, id: match[1].toLowerCase() };
  } catch { return null; }
}

export function validPrincipal(identity) {
  return (identity?.kind === 'student' || identity?.kind === 'judge') &&
    typeof identity.userId === 'string' && NOTICE_UUID.test(identity.userId);
}

export async function hasInstructorMembership(db, identity) {
  if (!validPrincipal(identity) || identity.kind !== 'student') return false;
  try {
    const { data, error } = await db.from('instructor_memberships')
      .select('user_id').eq('user_id', identity.userId).maybeSingle();
    return !error && data?.user_id?.toLowerCase() === identity.userId.toLowerCase();
  } catch { return false; }
}
