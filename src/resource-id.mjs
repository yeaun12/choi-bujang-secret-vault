// 8단계 제작 1: 자료 종류를 구분하는 논리적 자원 ID입니다.
// 실제 사용자 권한과 메모 소유권은 이 ID만으로 확인할 수 없습니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export const RESOURCE_ZONES = Object.freeze({
  NOTE: 'note',
  INSTRUCTOR_NOTICE: 'instructor_notice',
});

export function resourceIdFor(zone, itemId) {
  if (!Object.values(RESOURCE_ZONES).includes(zone)
      || typeof itemId !== 'string' || !UUID.test(itemId)) {
    return null;
  }
  return `${zone}:${itemId.toLowerCase()}`;
}

// 현재 존재하는 메모 API 요청의 정확한 경로만 분류합니다.
// 자료 ID는 URL 경로에서만 추출하고 쿼리·헤더·본문으로 선택하지 않습니다.
export function noteResourceFromApiPath(pathname) {
  if (pathname === '/api/notes') {
    return Object.freeze({ zone: RESOURCE_ZONES.NOTE, resourceId: 'note:collection' });
  }
  if (typeof pathname !== 'string') return null;
  const match = /^\/api\/notes\/([0-9a-f-]{36})$/iu.exec(pathname);
  if (!match) return null;
  const resourceId = resourceIdFor(RESOURCE_ZONES.NOTE, match[1]);
  if (!resourceId) return null;
  return Object.freeze({ zone: RESOURCE_ZONES.NOTE, resourceId });
}

// 강사 공지 API/테이블은 아직 없으므로 자원 ID 이름 공간만 예약합니다.
// 실제 공지 경로나 강사 권한을 여기서 만들어 신뢰하지 않습니다.
export function instructorNoticeResourceId(noticeId) {
  return resourceIdFor(RESOURCE_ZONES.INSTRUCTOR_NOTICE, noticeId);
}
