
 // 6단계: 엔진이 확인한 기기 등록 여부로 접근을 판정합니다.
 // 사용자와 기기의 연결 및 인증서 검증은 공식 엔진이 담당합니다.

export const RULE_IDS = Object.freeze(['device_registered']);

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
