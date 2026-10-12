// ALEPH SDP 엔진이 신원·기기·경로를 검증한 요청만 판정합니다.
// 사용자·기기 연결은 엔진이 확인하며, 브라우저 제공 정보나 임의의 ID 목록은 신뢰하지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  // 등록 확인과 엔진이 제공하는 가명 주체/기기 식별자가 모두 있어야 허용합니다.
  // 검증되지 않은 입력은 fail-closed 처리합니다.
  const verifiedDevice = request?.deviceRegistered === true
    && typeof request.subjectId === 'string'
    && request.subjectId.trim().length > 0
    && typeof request.deviceId === 'string'
    && /^[0-9a-f]{16}$/u.test(request.deviceId);

  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: verifiedDevice ? 'allow' : 'deny',
    reasonCode: verifiedDevice ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}
