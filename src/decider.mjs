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

// 8단계 제작 2: 엔진이 확인한 메서드·경로와 일치하는 자료 구역만 통과합니다.
// 이 정보에는 메모의 저장된 소유자가 없으므로 실제 소유권은 자료 API가 확인합니다.
const NOTE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const NOTE_ITEM_METHODS = new Set(['GET', 'PUT', 'DELETE']);
const NOTE_COLLECTION_METHODS = new Set(['GET', 'POST']);
const AUTH_METHODS = new Set(['POST', 'PUT', 'DELETE']);
const NOTICE_COLLECTION_METHODS = new Set(['GET', 'POST']);
const NOTICE_ITEM_METHODS = new Set(['GET', 'PUT']);

export function classifyResourceRoute(request) {
  if (request?.service !== 'notes' ||
      typeof request?.subjectId !== 'string' || !request.subjectId.trim() ||
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

  // 강사 공지는 독립된 경로로 식별합니다. 서버 API에서 강사 등록을 재확인합니다.
  if (path === '/api/instructor-notices' &&
      NOTICE_COLLECTION_METHODS.has(method) &&
      route === `${method} /api/instructor-notices`) {
    return { zone: 'instructor_notice', resourceId: 'instructor_notice:collection' };
  }
  if (path.startsWith('/api/instructor-notices/') &&
      NOTICE_ITEM_METHODS.has(method) &&
      route === `${method} /api/instructor-notices/:id`) {
    const id = path.slice('/api/instructor-notices/'.length);
    if (NOTE_UUID.test(id)) {
      return { zone: 'instructor_notice', resourceId: `instructor_notice:${id.toLowerCase()}` };
    }
  }

  for (const prefix of ['/api/notes', '/notes']) {
    if (path === prefix && NOTE_COLLECTION_METHODS.has(method) &&
        route === `${method} ${prefix}`) {
      return { zone: 'note', resourceId: 'note:collection' };
    }

    const match = path.startsWith(`${prefix}/`)
      ? /^([^/]+)$/.exec(path.slice(prefix.length + 1))
      : null;
    if (!match || !NOTE_ITEM_METHODS.has(method) ||
        route !== `${method} ${prefix}/:id`) continue;

    const id = match[1];
    if (NOTE_UUID.test(id)) {
      return { zone: 'note', resourceId: `note:${id.toLowerCase()}` };
    }

    // 7단계 공식 로컬 연습은 /notes/demo라는 가상 자원을 사용합니다.
    if (prefix === '/notes' && id === 'demo' && method === 'GET' &&
        request.classId === 'class_fixture' &&
        request.projectId === 'project_fixture' &&
        request.signals?.source === 'judge_fixture') {
      return { zone: 'note', resourceId: 'note:fixture_demo' };
    }
  }

  // 공지 수정의 강사 권한 검사는 서버 DB에서 재확인합니다.
  // /notes/export처럼 자원과 기능이 충돌하는 경로도 열지 않습니다.
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
