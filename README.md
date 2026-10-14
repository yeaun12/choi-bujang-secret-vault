# BYTE BACK 방어전 시작 틀 R5

## 10단계: 백업에서 자료실을 되살립니다 — 현재 구현과 복구 절차

이 문서의 **10단계 복구 절차**는 현재 `main`에서 구현한 동작을 설명합니다. 복구 대상은 공식 서명으로 검증된 시험 계정 **B의 지정 메모 한 건**이며, 다른 메모·강사 공지·기존 정책·감사 이력을 초기화하지 않습니다. 운영 자료실 주소는 `https://choi-bujang-secret-vault-blush.vercel.app/`, 복원 경로는 **`POST /api/restore`**입니다. `aleph.config.json`의 `step=10`, `restoreRoute="/api/restore"`, `allowedRoutes`의 `POST /api/restore`와 배포 `/aleph.json`에도 같은 경로가 기록됩니다.

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

**소스/배포 확인:** GitHub 저장소 `https://github.com/yeaun12/choi-bujang-secret-vault`, 운영 자료실 `https://choi-bujang-secret-vault-blush.vercel.app/`. 제출 직전에는 `git log -1 --oneline`으로 현재 커밋을 확인하고 `npm run bundle`로 해당 커밋의 `artifacts/submission.json`을 생성합니다. `aleph.config.json.step=10`, `restoreRoute="/api/restore"`입니다.

**문서 보충:** 이 README 자체에 10단계의 복구 조건·검증 방법·재시험 결과·미실행 항목을 모두 기술했습니다. 보조 구현 문서 `docs/STAGE10_LIVE_PROOF_CONTRACT.md`를 읽지 않아도 위 절차를 판단할 수 있습니다. **수정 이전 방식(과거 기록)**에 있던 프로세스 내부 직접 GET 호출 방식은 현재 사용하지 않으며 실제 HTTPS 요청으로 재시험합니다. 1~9단계의 세부 개발 이력은 저장소의 이전 Git 커밋에 남아 있습니다.
