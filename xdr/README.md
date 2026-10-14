# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 심판 격리 환경에서 지킬 것

심판은 인터넷 없이 `decide.mjs` 한 파일을 불러와 경보마다 바로 답을 받습니다. 이 파일이 돌지 못하면 건수를 셀 수 없어 `XDR_DECIDE_NOT_RUNNING` 으로 끝납니다.

- `decide.mjs` 에는 `import` 문을 두지 않습니다. 필요한 패턴은 `patterns.json` 에서 파일 맨 위 상수로 옮겨 적습니다.
- 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 그 파일 안에서 혼자 계산해 답합니다. 경보 하나에 2초 안에 답합니다.
- `confidence`(확신도)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 `decide` 가 스스로 0~1 로 매긴 값입니다.
- `xdr/alerts.log` 기록과 판정기 연결은 `respond.mjs` 같은 다른 파일에서 합니다. `decide.mjs` 는 판단 결과만 돌려줍니다.

인터넷을 끈 상태에서 `npm run xdr:run -- <moduleKey>` 를 돌려도 같은 결과가 나오면 심판에서도 같은 결과가 나옵니다.

## XDR-04 보너스 저장점: Persistence

- `npm run xdr:persistence:read`: 가상 경보 24건에서 시각·출발 주소·계정·규칙 수준·설명만 안전하게 추출합니다. `decide.mjs`와 분리했습니다.
- `xdr/persistence/patterns.json`: MITRE T1543/T1053 탐지 조건과 근거. 격리 심판은 이를 `decide.mjs`에 내장한 상수로 처리합니다.
- `npm run xdr:run -- persistence`: `xdr/persistence/result.json` 재생성, 예상 block 8 / alert 8 / record 8. 생성 결과는 판정 코드가 아닙니다.
- `npm run xdr:persistence:replay`: `respond.mjs`로 로컬 만료형 거부 후보와 알림을 시험합니다. `xdr/alerts.log`, `xdr/persistence/deny-rules.json`은 Git 추적에서 제외합니다.
- `enforceZtnaDecision(baseDecision, trustedSourceIp)`는 기존 ZTNA 판단 결과 뒤에서 신뢰한 출발지 IP로만 로컬 거부 후보를 적용하는 별도 어댑터입니다. 기존 `src/decider.mjs`와 그 응답 계약은 변경하지 않았습니다. **현재 실제 운영 ingress/SDP 릴레이에는 연결되지 않으며, 운영 사용자 격리의 증거가 아닙니다.**
- `npm run xdr:test`: 기존 XDR 및 읽기·판정·알림·안전 조건 테스트입니다. 공식 심판 판정은 별도입니다.

## XDR-05 보너스 저장점: Privilege Escalation

- 판정 규칙 위치: `src/decider.mjs`가 기존 ZTNA 접근 결정을 내리며, `docs/DECIDER_REQUEST.md`의 18필드 요청/5필드 응답 계약을 따릅니다. 원본 규칙을 수정하지 않았습니다.
- `npm run xdr:privilege:read`: 가상 Wazuh 경보 26건을 시각·출발 주소·계정·규칙 수준·설명의 5필드만 출력하고 비밀값처럼 보이는 내용을 마스킹합니다.
- `xdr/privilege/patterns.json`: MITRE T1068/T1078 기반 관리자 그룹 추가·이례적인 권한 사용·세션 승격 및 추가 조사 조건과 한 줄 근거.
- `npm run xdr:run -- privilege`: 오프라인 판정기 `xdr/privilege/decide.mjs`만 독립적으로 불러 `result.json` 생성 (기준: block 9, alert 8, record 9). 원본 경보 변경 없음.
- `npm run xdr:privilege:replay`: `respond.mjs`가 **검증된 block 경보만** 15분 만료형 계정+출발지별 로컬 거부 후보로 보관하고 `xdr/alerts.log`에 정제된 알림 한 줄을 기록합니다. 파일은 Git 추적에서 제외합니다.
- `enforceZtnaDecision(baseDecision, trustedIdentity)`는 신뢰된 인증 계정 매핑과 출발지 IP가 함께 제공될 때만, 기존 ZTNA 허용 결정을 공식 응답 5개 필드 안에서 거부 결정으로 변경하는 **별도 시험 어댑터**입니다. Wazuh의 `srcuser`를 SDP `subjectId`와 동일하다고 추정하지 않습니다.
- **제약:** 실제 SDP 릴레이에 연결하지 않았고, 인증 토큰·세션 발급자에 대한 회수 API도 호출하지 않습니다. 따라서 로컬의 세션 거부 후보 9건은 실제 세션 회수 9건을 의미하지 않습니다. 공식 심판 판정도 별도입니다.
- `npm run xdr:test`: 기존 XDR 6모듈과 보너스 회귀 시험을 모두 실행합니다.
