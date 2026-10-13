// 6단계: 엔진이 확인한 기기 등록 여부로 접근을 판정합니다.
// 사용자와 기기의 연결 및 인증서 검증은 공식 엔진이 담당합니다.

export const RULE_IDS = Object.freeze(['device_registered']);

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

// 기존 6단계 판정은 변경하지 않습니다.
export async function decide(request) {
  const registered = request?.deviceRegistered === true;

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
