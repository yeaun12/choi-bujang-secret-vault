# BYTE BACK 방어전 시작 틀 R5

## 보너스 xdr-06 저장점 (2026-10-14)

- 「자료 빼돌리기를 잡아 냅니다」: `xdr/exfiltration/read-alerts.mjs`, `patterns.json`, 독립 `decide.mjs`, `respond.mjs`, `scripts/xdr-run-exfiltration.mjs`에 합성 경보 분석·로컬 차단 후보를 구현했습니다.
- 기존 ZTNA 판정기 `src/decider.mjs`, 원본 `xdr/fixtures/exfiltration.json`, `aleph.config.json.step=12`, 인증 발급자·허용 경로·원본 API 주소는 변경하지 않았습니다.
- 재현: `npm run xdr:exfiltration:read` → `npm run xdr:run -- exfiltration` → `npm run xdr:exfiltration:replay` → `npm run xdr:test` → `npm run test:stage12`. 예상 30건은 block 10 / alert 10 / record 10이며 정상 오차단 0건을 확인합니다.
- 로컬 후처리는 출발 계정·주소·목적지별 15분 만료 차단 후보와 정제 로그까지만 담당합니다. **운영 SDP에는 목적지 필드가 없어 실제 차단 연동과 공식 심판 판정은 별도**입니다. 상세 내용은 `xdr/README.md`를 참고합니다.

## 보너스 xdr-05 저장점 (2026-10-14)

- 「권한 가로채기를 잡아 냅니다」: `xdr/privilege/read-alerts.mjs`, `patterns.json`, 독립 `decide.mjs`, `respond.mjs`, `scripts/xdr-run-privilege.mjs`로 구성된 보너스 판정·로컬 후처리.
- 기존 `src/decider.mjs` 규칙, `aleph.config.json.step=12`, 로그인 발급자·허용 경로·원본 API 설정 및 `xdr/fixtures/privilege.json`은 변경하지 않음.
- 재현: `npm run xdr:privilege:read`, `npm run xdr:run -- privilege`, `npm run xdr:privilege:replay`, `npm run xdr:test`, `npm run test:stage12`. 기준 분류는 합성 경보 26건 중 block 9 / alert 8 / record 9.
- 계정+출발지별 15분 로컬 거부 후보와 안전한 알림만 구현. **운영 SDP 연계·실제 세션 토큰 회수·공식 심판 통과는 별도 확인 항목**. `xdr/README.md`에 구체적인 범위를 설명함.


## 12단계: 탈환 작전실을 완성합니다 — 저장점 구현 및 재현 절차

**작성 기준:** 12단계 작업 브랜치 `stage12-warroom-work`의 최신 소스입니다. `aleph.config.json.step=12`와 `GET /api/war-room` 허용 경로를 반영했습니다. **12단계 Production 배포·실제 UI/API 교차 실측·공식 41종 총공세 판정은 아직 완료되지 않았습니다.** 최종 제출 전 배포 커밋과 제출 묶음 커밋을 대조해야 합니다.

### 기능과 근거의 범위

| 구성 | 학생이 구현한 부분 | 실제 근거와 검증 상태 |
|---|---|---|
| 판정 규칙 | `src/decider.mjs` — `device_registered`, `step_up_required`, `resource_scope`의 세 규칙 | 코드에서 규칙 이름·개수를 읽어 표시. 실시간 운영 엔진 판정 성공 건수를 뜻하지 않음 |
| 탐지 | `src/detect.mjs` — 제공된 가상 사건 계약에서 10분 초과 조회량 탐지, `propose_revocation` 제안 | `npm run detect:test`는 로컬 연습. 운영 사건 전달과 실제 회수 집행은 근거가 없어 **미실행/미확인** |
| 기기 승인·접속 앱 | `public/index.html`, `src/stage11-device-proof.mjs`, `api/device/*` — WebAuthn 기기 등록과 요청별 서명 검사 | 11단계 **공식 심판 통과**. 현재 운영 배포는 11단계 커밋 `48f94a4`이며 12단계 화면은 아직 미배포 |
| 자료실·구역 제어 | `api/auth`, `api/notes`, `api/instructor-notices`, `src/resource-api-auth.mjs` | 기존 검증된 로그인·메모 소유권·공지 구역 보호 유지. 타인 메모·회수 신원 복합 공격의 12단계 실측은 미실행 |
| 복구·감사 | `api/restore.js`, `src/stage10-*`, DB `stage10_note_backups`·`stage10_restore_audit` | 원본 메모 본문 없이 **서버 DB의 실제 사본 수·최신 생성 시각·감사 건수·마지막 종류만** 조회. 기록의 존재가 성공 판정은 아님 |
| 탈환 작전실 | `api/war-room.js`, `src/stage12-war-room.mjs`, `public/index.html` | 학생 JWT+서명된 WebAuthn 요청으로 `GET /api/war-room` 조회. 응답 요청 ID·확인 시각과 동일한 서버 요약 로그로 대조; 본문·사용자 ID·기기 키 비공개 |
| 자체 통합 검증표 | `public/stage12-check-matrix.mjs`와 화면의 안전한 조회 버튼 | 1~11단계 정상·금지 및 12단계 자체 점검 **학생 선정 24개 시나리오**. 실행한 안전한 GET에만 HTTP 상태·ID·시각 기록. 공식 **41종 공격과 다른 집합** |

작전실 API는 **로그인만으로는 조회 불가**이며 등록된 기기의 서명이 없는 학생 요청은 403, 비인증 요청은 401이 기대됩니다. 이 두 HTTP 응답과 DB의 실제 표시 수치는 Production 배포 이후 직접 대조해야 하며, 현재 통과한 단위 테스트를 운영 HTTP 실측이라고 표현하지 않습니다. 검증표의 `클라이언트 요청 ID`는 브라우저 자체 생성 구분자이고 서버 로그와 연동됐다는 증거가 아닙니다. 서버가 반환한 ID만 `서버 요청 ID`로 표시합니다. 미실행·네트워크 실패를 통과로 바꾸지 않습니다.

### 제공 엔진과 학생 코드의 출처

**운영 주체가 제공한 엔진:** *ALEPH SDP 엔진*이 인증된 신원·기기·요청 경로 정보를 검증하고 계약에 맞는 판정 요청을 전달합니다. 요청·응답 형식은 `docs/DECIDER_REQUEST.md`에 정리된 **18개 입력 필드와 5개 응답 필드**를 따릅니다. 원래 엔진의 구현물(`student-kit/sdp-core/decision-contract.mjs`의 계약 출처)은 이 저장소의 학생 개발 산출물로 취급하지 않습니다. 엔진 내부 검사·접속 회수 집행이 학생 코드에서 모두 구현됐다고 주장하지 않습니다.

**학생이 작성·수정한 부분:** 이 저장소의 판정기(`src/decider.mjs`), 탐지 규칙(`src/detect.mjs`), 가상 자료실 API, PWA·WebAuthn 접속 흐름, 단일 메모 복구, 작전실 집계·검증표입니다. `src/detect.mjs`의 반환값 `propose_revocation`은 **회수 제안**일 뿐 실제 세션 회수 완료를 의미하지 않습니다. XDR 실습 경보(`xdr/`)도 수업용 가상 데이터이고 운영 침해사고 로그가 아닙니다.

### 설치와 실행 순서 (Windows CMD, 저장소 루트)

1. 새 PC에서는 `git clone https://github.com/yeaun12/choi-bujang-secret-vault.git` 후 `cd choi-bujang-secret-vault`를 실행합니다. 기존 PC에서는 `git status --short`로 변경 사항을 먼저 확인하고, 작업 브랜치에 맞춰 `git pull --ff-only origin stage12-warroom-work`를 실행합니다. **최종 제출 때는 12단계 저장점 커밋을 `git log -1 --oneline`으로 재확인**합니다.
2. Node.js 22 이상에서 `npm install`(재현 가능한 잠금 파일 설치에는 `npm ci`)을 실행합니다. 설치 시 저장소에 실제 사용자 토큰이나 서버 전용 설정값을 추가하지 않습니다.
3. `npm run decider:test` → `npm run detect:test` → `npm run test:stage11` → `npm run test:stage12-war-room` → `npm run test:stage12-matrix` → `npm run test:stage12` → `npm run build -- --local` 순서로 실행합니다. **로컬 테스트는 가상 요청을 대상으로 하며 실제 심판 판정이 아닙니다.** `npm run build -- --local`은 정적 자산을 검사할 뿐 API 서버를 로컬에서 실행하지 않습니다.
4. 실제 자료실과 `api/*` 서버리스 함수를 실행하는 환경은 **Vercel Production**입니다. 프로젝트가 올바른 Git 커밋과 서버 전용 환경변수 설정으로 배포되어야 동작합니다. Production 주소: `https://choi-bujang-secret-vault-blush.vercel.app/`. 사용자는 로그인 → 기기 등록·승인 → 기기 서명으로 자료실 열기 → 탈환 작전실 `실제 서버 요약 조회` → `안전한 조회만 실측` 순서로 확인합니다. **현재 Production은 11단계 배포이며 12단계 배포 전에는 새 화면이 보이지 않는 것이 정상입니다.**
5. `api/war-room.js` 응답의 `requestId`, `observedAt`, `recovery.backupCount`, `recovery.auditCount`를 가린 서버 기록의 `s12_war_room_snapshot`과 대조합니다. 등록된 기기가 없는 학생 요청·익명 요청은 각각 정상 자료 접근이 거부되어야 합니다. 개인 메모의 본문이나 인증 토큰을 로그에 복사하지 않습니다.

### 중지·되돌리기·복구 절차

- **로컬 실행 중지:** 실행 중인 테스트 또는 개발용 명령은 해당 CMD에서 종료 여부를 확인하고, 장시간 실행 프로세스라면 `Ctrl+C`로 중지합니다. `npm run build -- --local`과 단위 테스트는 완료 후 자동 종료됩니다. 서버리스 Production 서비스는 로컬 CMD 종료로 중지되지 않습니다.
- **운영 서비스 중단·롤백:** Vercel 대시보드에서 현재 배포 커밋과 상태를 확인하고, 필요한 경우 관리자 권한으로 마지막 정상 배포를 선택해 복구합니다. 배포 전후 HTTP 정상·거부 결과를 다시 확인합니다. **이 절차는 자동으로 실행되지 않았고 실제 롤백을 수행했다고 주장하지 않습니다.**
- **작업 파일 되돌리기:** `git status --short`, `git diff` 및 `git log -1 --oneline`으로 12단계 변경과 다른 작업을 구분하고, 되돌릴 파일과 사라질 내용을 검토한 뒤 승인받아 해당 파일만 안전하게 복구합니다. `git reset --hard`와 무조건적인 DB 초기화는 사용하지 않습니다.
- **10단계 제한된 시험 정책 복구:** `node scripts/stage10-policy-diff.mjs`로 안전 사본 출처와 시험 정책 차이를 확인하고, `node scripts/stage10-policy-restore.mjs --preview`로 **격리된 테스트 대상에 한해** 변경을 미리 봅니다. 명확한 시험 승인 없이 `--apply`를 사용하지 않습니다. 운영 정책이나 다른 사용자의 자료를 이 스크립트로 고치지 않습니다.
- **운영 메모 한 건 복구:** `POST /api/restore`는 공식 심판이 서명으로 확인한 **시험 계정 B**의 권한 범위에만 허용됩니다. 사본·소유자·해시·감사 원본을 확인하고 사전 미리보기 후 복구하며, 일반 학생 계정은 호출할 수 없습니다. 복구 후 정상·금지 HTTP 재시험과 감사 기록을 다시 확인합니다. 복구하려고 원본 메모나 기존 DB를 덮어쓰거나 초기화하지 않습니다.

### 제출 전 증거 구분과 보안

- 현재 직접 실행·보고된 항목: 제작 1 단위 테스트 **4/4**, 제작 2 단위 테스트 **5/5**; GitHub Actions 기존 10단계 **73/73**, 11단계 **81/81**. 12단계 저장점 변경 후 `npm run test:stage12`는 별도로 실행해야 합니다. 이는 **코드의 회귀 검증**이지 41종 실제 공격 총공세 성공이 아닙니다.
- **미실행:** 새 12단계 Production UI 수치·서버 로그 대조, 12단계 정상 및 차단 실제 API 교차 시험, ALEPH SDP 엔진과 운영 탐지/회수 연계, 41종 공식 총공세. 실행한 뒤에만 수치·시각·상태를 갱신합니다.
- 실제 비밀번호·JWT·서버 키·기기 개인키·연락처·메모 본문은 README·Git·시험표·제출 JSON에 포함하지 않습니다. `SUPABASE_URL`과 `SUPABASE_SECRET_KEY` 등 서버 전용 설정은 **사용자가 Vercel 비밀 환경변수로 별도 관리**합니다. 이 문서는 키 값을 제공하거나 요구하지 않습니다.
- 현재 `aleph.config.json.step=12`이고 빌드·배포 식별·자기 점검 스크립트에 12단계 지원을 추가했습니다. **Production 배포 이후** `public/aleph.json` 커밋과 작전실 화면/서버 실측 수치를 대조한 뒤 `npm run bundle`로 로컬 `artifacts/submission.json`을 만듭니다. `bundle-notes.json`과 `artifacts/submission.json`을 커밋하지 않습니다.

---

## 11단계: 나만의 접속 앱을 완성합니다

**현재 구현 방식:** 기존 자료실에 설치형 웹앱(PWA)과 WebAuthn 기반 기기 등록·요청 서명 검증을 추가합니다. 설치 여부·화면 버튼·클라이언트 플래그만으로 기기를 승인하지 않으며, 서버의 등록 공개키와 매 요청의 실제 서명을 확인한 뒤에만 일반 사용자 자료 API를 엽니다. 기존 1~10단계 정책·메모·감사 기록은 변경하지 않습니다.

### 제작 1: 설치형 웹앱과 기기 상태 표시

- `public/manifest.webmanifest`: 앱 이름, 범위, 시작 화면, standalone 모드 및 SVG 아이콘을 선언합니다. `public/index.html`에 manifest 링크·설치 버튼·온라인 상태·기기 상태 표시를 추가했습니다. 별도의 네이티브 프로그램이나 브라우저 저장형 기기 키를 만들지 않습니다.
- `public/sw.js`: 공개 오프라인 안내 페이지·아이콘·manifest만 캐시합니다. **메모·공지·로그인·인증 토큰·API 응답·index.html은 캐시하지 않습니다.** 오프라인에서는 `public/offline.html`에서 연결 필요를 안내하고 개인 자료를 표시하지 않습니다.
- 앱이 설치되었다는 사실은 기기 승인과 무관합니다. 상태는 서버에서 받은 등록 결과와 보호 API의 서명 검증 성공 여부를 구분해 표시합니다.

### 제작 2: 승인 요청과 서명된 보호 요청

1. 로그인 이후 `GET /api/device`로 **서버에 등록된 인증기가 있는지** 확인합니다. 미등록/서명 전에는 메모 목록과 작성 화면을 표시하지 않습니다. 등록된 인증기가 있더라도 **서명을 제출하기 전**에는 자료가 열리지 않습니다.
2. '이 기기 등록 요청'은 `POST /api/device`의 `begin`으로 서버에 90초 유효한 일회용 과제를 등록합니다. 브라우저 WebAuthn `navigator.credentials.create`가 인증기에서 ES256 공개·개인키를 생성하고 사용자 검증을 요구합니다. `finish`는 서버가 RP ID·정확한 origin·일회용 challenge·사용자 검증·공개키를 검증한 경우에만 인증기 공개키를 서버 `stage11_device_credentials`에 등록합니다. 등록 이후 요청마다 인증기의 서명이 추가로 필요합니다.
3. 자료 요청 전 `POST /api/device/challenge`로 요청 **HTTP 메서드·정확한 경로·쿼리·원문 본문 SHA-256**이 묶인 서버 과제를 발급받습니다. `navigator.credentials.get`의 사용자 검증을 거친 서명 응답만 보호 API로 전달합니다. 개인키와 기기 자격 증명은 `localStorage`, `sessionStorage`, `IndexedDB`나 Git에 저장하지 않습니다. 기존 로그인 access token은 실행 중 JS 메모리에서만 사용하고 refresh token은 기존 HttpOnly 쿠키 규칙을 유지합니다.
4. 서버는 `src/stage11-device-proof.mjs`에서 **일회용 과제 소모 → 요청 메서드·경로·본문 SHA-256 일치 → 승인된 사용자별 공개키의 ES256 서명·RP ID·origin·사용자 검증 검증** 순서로 판단합니다. 학생 메모와 강사 공지의 보호 API는 서명이 없거나 요청이 바뀌면 HTTP **403**으로 거부합니다. 이미 한 번 사용한 과제는 재사용하지 않습니다. 공식 심판 서명 신원은 이전 단계 검증용 별도 발급자 경계에서 처리하며, 학생 앱용 기기 등록을 대체하는 증거로 취급하지 않습니다.
5. 서버 전용 DB 테이블과 RLS/직접 권한 차단은 `supabase/stage11_device_registry.sql`로 추가합니다. 기존 `public.notes`의 데이터와 정책 및 10단계 감사 테이블에는 변경을 가하지 않습니다.

### 검증과 제출 전 확인

- 합성 암호학 단위 시험: 유효 등록키의 메서드·경로·본문에 대한 서명 검증, **서명 없는 요청·서명 후 경로 변경·본문 변조·서명 재사용 거부**, 이전 단계 회귀 검사.
- **실제 브라우저 확인(2026-10-14, 사용자 직접 수행·결과 보고):** (1) 최신 11단계 화면 표시, (2) 로그인 후 기기 승인 전 개인 자료 비노출, (3) WebAuthn 기기 등록 및 서명 요청 후 기존 메모 화면 정상 표시. 이 결과는 사용자 확인에 근거하며 자동화된 브라우저 시험 로그가 아닙니다.
- **별도 미확인:** 새로고침·오프라인·서명 취소 시 모든 화면 상태는 직접 재시험하지 않았습니다. 다만 11단계 공식 심판에서 서명 없는 요청 및 서명 뒤 경로·본문 변경 요청 차단을 인정받아 **11단계는 통과**했습니다.
- **로컬 재현:** `npm install`, `npm run test:stage11`, `npm run decider:test`, `npm run build -- --local`, `npm run bundle`. 사용자 CMD 확인: `npm install` 성공(취약점 0), `npm run test:stage11` 81/81 통과. `npm run bundle`은 **11단계 저장점 커밋을 PC에 가져온 뒤 새로 실행**해야 합니다.
- **11단계 저장점:** `aleph.config.json.step=11` 유지. 운영 URL `https://choi-bujang-secret-vault-blush.vercel.app/`; 11단계 Production 커밋 `48f94a46c5932c036f76d794cc4c72cb67e5e5ac` 배포 `READY` 확인. 이 문서만 갱신한 저장점 커밋은 배포 반영 및 `npm run bundle` 재실행으로 별도 확인합니다. `judgeIssuer`, 로그인 발급자, 원본 API 주소, 허용 경로, `RULE_IDS`의 기능은 변경하지 않습니다.
- **제출 평가:** PWA 화면·기기 등록/서명 API 구현과 브라우저 사용자 확인은 완료됐으나, **11단계 공식 심판 통과 결과를 사용자에게서 확인했습니다.** 이는 12단계 통과나 총공세 41종 방어의 증거가 아닙니다.

---

## 10단계: 백업에서 자료실을 되살립니다 — 이전 단계 복구 절차 보존

이 문서의 **10단계 복구 절차**는 현재 `main`에서 구현한 동작을 설명합니다. 복구 대상은 공식 서명으로 검증된 시험 계정 **B의 지정 메모 한 건**이며, 다른 메모·강사 공지·기존 정책·감사 이력을 초기화하지 않습니다. 운영 자료실 주소는 `https://choi-bujang-secret-vault-blush.vercel.app/`, 복원 경로는 **`POST /api/restore`**입니다. 10단계 당시 설정은 `step=10`이었고, 현재 `aleph.config.json`은 `step=12`입니다. `restoreRoute="/api/restore"`, `allowedRoutes`의 `POST /api/restore`와 배포 `/aleph.json`에도 같은 경로가 기록됩니다.

### 백업 검증

**안전 정책 사본(제작 1~2).** 공식 통과한 8단계 및 9단계 커밋의 `src/decider.mjs` Git blob이 같은 안전 버전(`3d8715d5aa11a548c72e7188028f7c2539af8ef8`)인지 검증한 뒤, 읽기 전용 비교로 현재 시험 정책과 다른 줄·영역을 확인합니다. 사본이 없거나 Git blob이 불일치하면 작업을 중단합니다. `node scripts/stage10-policy-diff.mjs`는 차이만 출력하고 운영 정책을 변경하지 않습니다. 시험 정책을 복원할 때는 `.stage10-sandbox/`의 **격리된 시험 파일**만 대상으로, 버전과 변경 범위 및 현재 파일 SHA-256을 미리 보여 줍니다. `node scripts/stage10-policy-restore.mjs --preview` 후 확인된 해시를 사용해 `--apply <미리보기_현재_SHA256> --confirm TEST_ONLY`로 승인해야 복원합니다. 복원 직전 원본 사본과 시험 파일을 재검증하고, 복원 뒤 정상 A 요청은 `allow`, B의 A 자료 요청은 `deny`, 미등록 기기는 `deny`, 이상 접속은 `step_up`인지 검사합니다. 이 과정에서 **운영 `src/decider.mjs`·다른 서비스 정책·운영 DB는 수정하지 않습니다.**

**비공개 메모 사본(제작 3).** 시험 B가 `POST /api/notes`로 새 메모를 생성하면 DB의 원자적 작업으로 원본 메모·비공개 사본(`stage10_note_backups`)·`backup_created` 감사 근거를 함께 기록합니다. 기존 B 메모는 **처음으로 인증된 PUT/DELETE가 실행되기 직전** 현재 행을 사본으로 기록합니다. 사본은 검증된 심판 실행 ID, B 신원, 메모 ID 및 저장 소유자에 귀속하며, 저장 후 별도 조회로 **ID·소유자·내용 SHA-256·사본 시각**을 대조합니다. 최초 `backup_created` 감사 근거의 해시도 별도로 검증합니다. 기존 사본은 나중의 변경 내용으로 덮어쓰지 않습니다.

**복원 전 재확인.** B의 메모 복구 요청을 받으면 사본을 다시 읽고 실제 본문의 SHA-256, 소유자, 메모 ID, 버전(`captured_at`), 원본 생성 감사 기록과 일치하는지 검사합니다. 미리보기에서는 현재 메모와 비교해 **변경될 항목(`changes`)과 사본 버전(`version`)**을 먼저 반환합니다. 쓰기 직전에 사본과 최초 감사 해시를 한 번 더 확인합니다. 사본 누락은 **404**, 무결성·출처·소유자 불일치는 **409** 등으로 복원을 중단하고, 검증되지 않은 데이터를 안전 사본으로 간주하지 않습니다. 특히 이미 변조되었거나 삭제된 메모를 복구 요청 시점에 새로 백업해 원본으로 둔갑시키지 않습니다.

### 한 건 복원

- **경로와 권한:** `POST /api/restore`에 심판 발급자의 ES256 서명·발급자·허용 대상·만료·신원 정보를 확인한 **시험 B**만 접근합니다. 익명은 401, 시험 A나 일반 학생은 403으로 거부합니다. `GET /api/restore`는 405입니다. 요청에 포함된 임의의 역할·소유자 주장을 신뢰하지 않습니다.
- **대상 지정 및 실행 전 확인:** 요청 본문은 `{"noteId":"<메모_UUID>"}` 한 건입니다(`id`, `note_id`, `memoId` 별칭 지원). `{"noteId":"<메모_UUID>","dryRun":true}`는 쓰기 없이 사본의 `version`, 변경될 `changes`, 소유자 및 해시 근거를 반환합니다. 요청에 `ownerId` 또는 `contentSha256`를 명시했다면 확인된 사본과 일치해야 실행합니다. 메모 ID를 생략한 요청은 해당 심판 실행의 **검증된 B 사본 중 현재와 다른 대상이 정확히 한 건**일 때만 허용하고, 아니면 400으로 거부합니다.
- **실제 복원:** 검증된 사본의 메모 **한 건만** 원본 제목·내용·생성 시각으로 수정하거나 삭제된 경우 같은 ID·소유자로 재생성합니다. 작업 후 DB에서 행을 재조회해 사본과 **ID(`id`), 저장 소유자(`ownerId`), 내용 SHA-256(`contentSha256`)**이 모두 일치하는지 재검증합니다. `backup.noteId`, `backup.ownerId`, `backup.contentSha256`과 복원 응답 및 DB 재조회 결과를 대조해 `match.all`을 산출합니다. 다른 메모를 일괄 복원하거나 기존 메모·공지·서비스 정책을 초기화하지 않습니다.

### 감사 기록 보존

`stage10_note_backups`의 검증된 원본 사본과 `stage10_restore_audit`의 기존 기록을 보존합니다. 복구 요청·거부·성공·재시험은 **추가 기록**으로 남기며 기존 감사 행을 삭제·수정하지 않습니다. 감사에는 실행 범위, 메모 ID, 이유 코드·본문 해시 등 필요한 검증 메타데이터만 기록하고 **메모 본문·토큰·비밀키는 기록하지 않습니다.** 응답의 `scope`에는 복원 대상이 한 건이고 다른 메모를 변경하지 않았다는 범위가 명시됩니다.

복구 자체가 DB에서 검증된 후 마지막 완료 감사 저장이 실패하면 **HTTP 503**, `restored:true`, `match.all:true`, `completionAuditVerified:false`, `retestVerified:false`로 보고합니다. 복구되지 않았다고 거짓 보고하지 않으며 후속 재시험을 성공으로 표시하지 않습니다. 복구 뒤 재시험 감사 저장에 실패해도 **HTTP 503**, `restored:true`, `retestVerified:false`, `retest.evidenceUnavailable:true`로 구분합니다. 기록을 확인할 수 없는 시험 건수는 임의 숫자가 아니라 `null`로 남깁니다.

### 복원 뒤 재시험

복구된 메모의 ID·소유자·본문 해시가 원본 사본과 일치한 뒤에만, 기존 API를 통한 **실제 HTTP 정상·금지 요청**을 실행합니다. 재시험 결과는 `retest`와 `postRestoreRetest`의 정상(`normal`)·금지(`forbidden`) 결과 및 `retests`의 개별 HTTP 상태로 기록합니다. 네트워크 실패·예상 외 응답을 통과로 처리하지 않고, 필요한 재시험이 실패하면 복구 여부와 별개로 **HTTP 503 / `retestVerified:false`**를 반환합니다.

**복구 직후 자동 HTTP 재시험:**

1. B의 복구된 자기 메모 `GET /api/notes/:id` → **200**, 응답 ID·본문 SHA-256은 백업과 일치.
2. 같은 메모 비인증 GET → **401**, 자료 비노출.
3. B가 `?owner_id=...`를 붙여 조회 → **400**, 쿼리 우회 거부.
4. 존재하지 않는 메모를 B가 GET → **404**.
5. 검증 가능한 시험 A 소유 메모가 있을 때 B가 해당 메모 GET → **404**. A 사본이 없어 실제 실행할 수 없다면 `retest.notRun=["foreign_denied"]`과 `not_run_no_verified_a_note`로 **미실행** 표시하고, 통과한 것으로 위장하지 않습니다.

**1~9단계 전체 재검증 순서(검증 절차):** 복구가 끝난 뒤 아래 순서로 정상 요청과 금지 요청을 다시 확인합니다. 위 5가지 자동 HTTP 재시험만으로 1~9단계 전체가 재시험됐다고 주장하지 않습니다.

1. **1~2단계 공개 자료 차단:** 비인증 `GET /data.json` → 404, 정적 메모 재노출 없음.
2. **3단계 로그인:** 비인증·잘못된 토큰의 메모 조회/생성 → 401; 유효한 로그인 사용자는 본인 메모 사용 가능.
3. **4~5단계 소유권·서버 API:** A 정상 자기 메모 GET은 200; B의 A 메모 GET·PUT·DELETE는 404; 직접 Supabase REST 자료 요청은 차단.
4. **6단계 기기 검사:** 등록 기기 정상 요청 `allow`, 미등록 기기 요청 `deny/device_not_registered`.
5. **7단계 추가 인증:** 정상 가상 사건은 `allow`, 복합 위험 신호는 `step_up`.
6. **8단계 자원 구역:** 강사 공지 정상 조회 유지, 일반 학생의 공지 작성·수정과 전체 목록 우회는 거부.
7. **9단계 이상 조회 탐지:** 동일 가명 주체의 10분 내 조회량 120건과 121건 경계에서 `observe`/`propose_revocation` 분기 확인.

**복구 성공 응답의 증거 필드:** `backup.verified`, `backup.creationAuditVerified`, `backup.creationAuditRereadBeforeRestore`, `backup.rereadBeforeWrite`, `backup.noteId`/`backup.ownerId`/`backup.contentSha256`, 복구 결과의 `id`/`ownerId`/`contentSha256`, `match.all`을 확인합니다. 실제 정상·금지 HTTP 재시험이 모두 통과했을 때만 `retestVerified:true`, `retest.complete:true`, `retest.normal[]` 및 `retest.forbidden[]`의 결과가 포함된 HTTP 200 성공을 반환합니다. 미실행 항목은 `retest.notRun`으로 따로 보고합니다.

### 실제 수행한 검증 증거와 수행 범위

아래 값은 **2026-10-14 Windows CMD에서 실행한 `npm run test:stage10`의 합성 메모·로컬 시험** 기록입니다. 공식 심판 계정의 운영 DB에서 복구했다고 주장하는 값이 아닙니다. 이번 실행의 테스트는 **73건 통과 / 0건 실패**, GitHub Actions 동일 테스트도 통과했습니다. 이 표의 ID·소유자는 가상 시험값이며 본문·토큰·비밀키는 기록하지 않습니다.

| 검증 대상 | 검증된 사본 | 복원한 메모 및 HTTP/API 응답 | 결과 |
| --- | --- | --- | --- |
| **B 변조 메모 한 건** | ID `10986737-cbed-40ee-a56c-e14bbf48b870`, 저장 소유자 `2b7353f8-5990-49c0-bbe3-d8cbe84e428e`, 본문 SHA-256 `f3148cbbed29f57344a10eba08c40c57be695ea6270f647cebfad7428307ef6e` | DB 재조회 및 복구 응답의 **ID·소유자·본문 SHA-256 모두 사본과 일치** | `STAGE10_TUPLE_PROOF` = 세 값 일치 |
| **B 삭제 메모 한 건** | ID `bdaf9a0f-121c-4ff5-87ec-0923a7d8eda1`, 저장 소유자 `2b7353f8-5990-49c0-bbe3-d8cbe84e428e`, 본문 SHA-256 `f3148cbbed29f57344a10eba08c40c57be695ea6270f647cebfad7428307ef6e` | 삭제 후 한 건 재생성, DB 재조회 및 복구 응답의 **ID·소유자·본문 SHA-256 모두 사본과 일치** | `STAGE10_TUPLE_PROOF` = 세 값 일치 |
| **사본 원본성·보존** | 합성 최초 `backup_created` 감사 근거·사본 재조회, SHA-256 대조 | 사본 누락/변조/감사 원본 불일치면 404 또는 409로 중단. 다른 메모와 이전 감사 기록 유지 | 합성 시험에서 확인 |
| **복원 뒤 정상 요청** | 복구된 B 메모 | 본인 B 조회 200, A 본인 조회 200, B의 다른 본인 메모 조회 200 | `STAGE10_POSTRESTORE_PROOF` |
| **복원 뒤 금지 요청** | 다른 소유자 메모와 익명 요청 | B→A 조회 404, A→B 조회 404, A→B 수정·삭제 404, 익명 B 조회 401 | `STAGE10_POSTRESTORE_PROOF` |
| **복원 후 HTTP 재시험 감사** | 합성 B 복구 직후 실행 | `persistedRetestEvents=5`, 정상·금지 HTTP 상태를 별도로 기록, 다른 메모 보존 `true` | 합성 시험에서 확인 |

**실제 재시험의 판별 기준:** 정상 요청은 실제 HTTP 200 및 복원된 본문 SHA-256 일치로 판정하고, 금지 요청은 직접 받은 401·400·404 등의 응답으로 판정합니다. 실패한 요청은 실패로 기록하고 실행하지 않은 요청은 `notRun`으로 기록합니다. 복구만 성공하고 감사 기록 저장이나 재시험이 실패하면 `restored:true`와 `retestVerified:false`를 구분해 반환합니다. **로컬 증거로 공식 심판의 운영 재시험 성공을 대체하지 않습니다.**

**실행 상태의 구분:** `npm run test:stage10`은 로컬 합성 B 메모와 시험 저장소를 사용한 회귀 검증이고, `npm run bundle`은 공개 배포에 대한 비인증 HTTP 자기 점검과 로컬 검증을 각각 표시합니다. **공식 심판 B의 실제 백업 생성→변조/삭제→운영 복구→1~9단계 전체 공격 재시험은 별도 증거가 확보되지 않아 미실행/미확인입니다.** 실행하지 않은 시험은 `notRun` 또는 **미실행**으로 그대로 남겨 두며, 로컬 통과를 운영 복원·심판 통과라고 쓰지 않습니다.

**재현 명령(로컬):**

```cmd
node scripts/stage10-policy-diff.mjs
npm run test:stage10
npm run bundle
```

---

## 1~9단계 기존 보안 기능 요약

기존 기능은 **유지**합니다. 10단계는 시험 정책과 B 메모 한 건에 관한 복구 작업이며 아래 기능이나 운영 정책을 전체 초기화하지 않습니다.

- **1~2단계:** 공개 정적 메모 제거. 현재 비인증 `GET /data.json`은 404이고 메모는 서버 API·DB에서 관리.
- **3단계:** 로그인 토큰 검증 후 개인 메모 접근. 익명 메모 API 요청은 401.
- **4~5단계:** 검증된 메모 소유자와 DB의 `owner_id` 확인. B가 A의 메모를 직접 조회·수정·삭제하면 404. 브라우저에서 Supabase 자료 API를 직접 사용하지 않음.
- **6~7단계:** 등록 기기 정책·위험 신호에 따른 `allow`, `deny`, `step_up` 판정 유지.
- **8단계:** 메모와 강사 공지 자원 구역 분리. 일반 사용자 공지 작성·수정 거부.
- **9단계:** 가명 주체의 10분 내 과다 조회 탐지 및 `propose_revocation` 제안 기능 유지.

**소스/배포 확인:** GitHub 저장소 `https://github.com/yeaun12/choi-bujang-secret-vault`, 운영 자료실 `https://choi-bujang-secret-vault-blush.vercel.app/`. 제출 직전에는 `git log -1 --oneline`으로 현재 커밋을 확인하고 `npm run bundle`로 해당 커밋의 `artifacts/submission.json`을 생성합니다. 현재 `aleph.config.json.step=12`, `restoreRoute="/api/restore"`입니다.

**문서 보충:** 이 README 자체에 10단계의 복구 조건·검증 방법·재시험 결과·미실행 항목을 모두 기술했습니다. 보조 구현 문서 `docs/STAGE10_LIVE_PROOF_CONTRACT.md`를 읽지 않아도 위 절차를 판단할 수 있습니다. **수정 이전 방식(과거 기록)**에 있던 프로세스 내부 직접 GET 호출 방식은 현재 사용하지 않으며 실제 HTTPS 요청으로 재시험합니다. 1~9단계의 세부 개발 이력은 저장소의 이전 Git 커밋에 남아 있습니다.
