// 6단계: 엔진이 확인한 기기 등록 여부로 접근을 판정합니다.
// 사용자와 기기의 연결 및 인증서 검증은 공식 엔진이 담당합니다.

export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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

  // 추가 인증 정보는 엔진이 확인해 준 계약 필드만 사용합니다.
  // 실제 재로그인 연계 가능 여부는 7단계 제작 3에서 따로 확인합니다.
  const stepUp = request?.stepUp;
  const recentlyVerified = stepUp?.verified === true &&
    Number.isInteger(stepUp.authAgeSeconds) &&
    stepUp.authAgeSeconds >= 0 &&
    stepUp.authAgeSeconds <= 300;

  if (unusual && !recentlyVerified) {
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
    ruleIds: ['device_registered'],
  };
}
