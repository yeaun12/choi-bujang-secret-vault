// 6단계: 엔진이 확인한 기기 등록 여부로 접근을 판정합니다.
// 사용자와 기기의 연결 및 인증서 검증은 공식 엔진이 담당합니다.

export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_scope']);

// 7단계 제작 1: 엔진이 전달한 가상 접속 정보만 읽습니다.
// judge_fixture는 심판용 가상 사건이며 실제 위치 증거가 아닙니다.
export function readStep7FixtureContext(request) {
  const signals = request?.signals;

  if (
    !signals ||
    typeof signals !== 'object' ||
    Array.isArray(signals) ||
    signals.source !== 'judge_fixture'
  ) {
    return null;
  }

  const knownText = (value) =>
    typeof value === 'string' &&
    value.trim().length > 0 &&
    value.trim().toLowerCase() !== 'unknown';

  if (
    !knownText(signals.region) ||
    !knownText(signals.network) ||
    !Number.isInteger(signals.hour) ||
    signals.hour < 0 ||
    signals.hour > 23
  ) {
    return null;
  }

  const events = request?.recentEvents;

  if (!Array.isArray(events) || events.length > 12) {
    return null;
  }

  for (const event of events) {
    if (
      !event ||
      typeof event !== 'object' ||
      Array.isArray(event) ||
      !knownText(event.kind) ||
      !Number.isInteger(event.ageSeconds) ||
      event.ageSeconds < 0 ||
      !Number.isInteger(event.count) ||
      event.count < 0
    ) {
      return null;
    }
  }

  return {
    source: 'judge_fixture',
    region: signals.region,
    network: signals.network,
    hour: signals.hour,
    recentEvents: events.map(({ kind, ageSeconds, count }) => ({
      kind,
      ageSeconds,
      count,
    })),
  };
}

// 7단계 제작 2: 심판 가상 사건에서 복합 이상 징후가 함께 나타날 때만
// 추가 인증을 요구합니다. 지역 변화 하나로 영구 거부하지 않습니다.
function requiresAdditionalVerification(context) {
  if (context === null) return false;

  const unusualHour = context.hour < 6 || context.hour >= 22;
  const unfamiliarNetwork = context.network.trim().toLowerCase() === 'unusual';
  const recentBurst = context.recentEvents.some((event) =>
    event.kind === 'risk_signal' &&
    event.ageSeconds <= 300 &&
    event.count >= 10
  );

  return unusualHour && unfamiliarNetwork && recentBurst;
}

// 8단계 제작 2: 엔진이 확인한 사용자(subjectId)·기기(deviceId)·메서드·정확한 경로가
// 모두 규칙표와 일치할 때만 개별 자료 구역을 엽니다. 경로 모양(:id)만 맞는 요청,
// 다른 사용자·다른 기기의 같은 경로, 규칙표에 없는 경로는 모두 거부합니다.
// 메모의 저장된 소유자·강사 등록은 자료 API가 DB에서 다시 확인합니다.
const AUTH_METHODS = new Set(['POST', 'PUT', 'DELETE']);
const NOTE_COLLECTION_METHODS = new Set(['GET', 'POST']);
const NOTICE_COLLECTION_READ = 'GET';
// 7단계 공식 로컬 연습의 가상 주체·기기·반·프로젝트입니다.
const FIXTURE_SUBJECT = Object.freeze({
  classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
});

// 자기 메모 읽기·수정 규칙. 자원 ID는 경로에서만 고르고 쿼리로 기능을 고르지 않습니다.
export const NOTE_OWNER_RULES = Object.freeze([
  Object.freeze({ ...FIXTURE_SUBJECT, method: 'GET', path: '/notes/demo', route: 'GET /notes/:id' }),
  Object.freeze({ ...FIXTURE_SUBJECT, method: 'PUT', path: '/notes/demo', route: 'PUT /notes/:id' }),
]);

// 강사 공지 작성·수정 규칙. 엔진이 확인한 강사 주체가 아직 없으므로 비어 있고,
// 일반 학생의 공지 작성·수정은 판정기에서 거부됩니다.
export const NOTICE_INSTRUCTOR_RULES = Object.freeze([]);

function matchesRule(rule, request) {
  return rule.classId === request.classId &&
    rule.projectId === request.projectId &&
    rule.subjectId === request.subjectId &&
    rule.deviceId === request.deviceId &&
    rule.method === request.method &&
    rule.path === request.path &&
    rule.route === request.route;
}

export function classifyResourceRoute(request) {
  if (request?.service !== 'notes' ||
      typeof request?.subjectId !== 'string' || !request.subjectId.trim() ||
      typeof request?.deviceId !== 'string' || !/^[0-9a-f]{16}$/u.test(request.deviceId) ||
      typeof request?.method !== 'string' ||
      typeof request?.path !== 'string' ||
      typeof request?.route !== 'string' ||
      request.path.includes('?') || request.path.includes('#') ||
      !Number.isInteger(request.queryLength) || request.queryLength !== 0) {
    return null;
  }

  const { method, path, route } = request;
  if (path === '/api/auth' && AUTH_METHODS.has(method) &&
      route === `${method} /api/auth`) {
    return { zone: 'auth', resourceId: 'auth:session' };
  }

  // 목록은 자료 API가 검증된 사용자의 owner_id로만 걸러 냅니다.
  for (const prefix of ['/api/notes', '/notes']) {
    if (path === prefix && NOTE_COLLECTION_METHODS.has(method) &&
        route === `${method} ${prefix}`) {
      return { zone: 'note', resourceId: 'note:collection' };
    }
  }
  if (path === '/api/instructor-notices' && method === NOTICE_COLLECTION_READ &&
      route === 'GET /api/instructor-notices') {
    return { zone: 'instructor_notice', resourceId: 'instructor_notice:collection' };
  }

  const owned = NOTE_OWNER_RULES.find((rule) => matchesRule(rule, request));
  if (owned) {
    return { zone: 'note', resourceId: `note:${path.slice(path.lastIndexOf('/') + 1)}` };
  }
  const notice = NOTICE_INSTRUCTOR_RULES.find((rule) => matchesRule(rule, request));
  if (notice) {
    return { zone: 'instructor_notice', resourceId: `instructor_notice:${path.slice(path.lastIndexOf('/') + 1)}` };
  }

  // 다른 사용자의 메모, 일반 학생의 공지 작성·수정, /notes/export 같은 기능 경로,
  // 규칙표에 없는 경로는 모두 열지 않습니다.
  return null;
}

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  const context = readStep7FixtureContext(request);
  const unusual = requiresAdditionalVerification(context);

  // 6단계 미등록 기기 거부 규칙을 가장 먼저 적용합니다.
  if (!registered) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 확인된 메서드·경로 이외에는 API에 접근을 허용하지 않습니다.
  // 구역 경로를 열어도 저장된 메모 소유권은 서버 API가 별도로 확인해야 합니다.
  const resource = classifyResourceRoute(request);
  if (resource === null) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'resource_access_denied',
      ruleIds: ['resource_scope'],
    };
  }

  // 추가 인증 정보는 엔진이 확인해 준 계약 필드만 사용합니다.
  // 실제 재로그인 연계 가능 여부는 7단계 제작 3에서 따로 확인합니다.
  const stepUp = request?.stepUp;
  const recentlyVerified = stepUp?.verified === true &&
    Number.isInteger(stepUp.authAgeSeconds) &&
    stepUp.authAgeSeconds >= 0 &&
    stepUp.authAgeSeconds <= 300;

  if (resource.zone !== 'auth' && unusual && !recentlyVerified) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['step_up_required'],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered', 'resource_scope'],
  };
}
