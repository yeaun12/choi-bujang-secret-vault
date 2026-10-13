# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계: 자료를 코드 밖으로 이동

2단계에서는 가상 메모를 공개 정적 파일과 GitHub 최신 버전에서 제거하고 Supabase의 `public.notes` 테이블로 옮깁니다. `owner_id`는 `uuid` 형식으로 미리 두되 `auth.users` 외래키는 연결하지 않습니다. 테이블은 RLS를 활성화하고 `anon`과 `authenticated` 역할에는 직접 자료 읽기 권한을 주지 않습니다.

브라우저는 더 이상 `/data.json`에서 메모를 읽지 않고 `/api/notes` 서버 함수를 호출합니다. 서버 함수는 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 Vercel 환경변수에서 읽으며, 서버 전용 키를 브라우저 파일·응답·로그에 포함하지 않습니다.

현재 단계에서는 `/api/notes` 자체에 사용자 인증을 적용하지 않습니다. 따라서 비로그인 사용자도 서버 API를 호출해 가상 메모를 읽을 수 있으며, 이것은 다음 단계에서 해결할 남은 약점입니다.

`public/data.json`은 최신 버전에서 제거하고, 루트 `data.json`에는 메모 본문을 남기지 않습니다. 다만 이전 공개 Git 커밋과 이전 Vercel 배포에는 과거의 가상 메모가 남아 있을 수 있습니다. 2단계 변경은 현재 버전의 노출을 줄이는 것이며 과거 공개 이력까지 제거한 것으로 간주하지 않습니다.

### 메모 노출 확인 절차

검증할 때 실제 가상 메모 문자열을 README나 Git 추적 파일에 기록하지 않습니다. 현재 `/api/notes` 응답에서 검증할 가상 메모의 제목과 본문을 일시적으로 확인한 뒤, 같은 문자열이 최신 Git 추적 파일과 공개 정적 결과물에 남아 있는지 검색합니다.

Git 최신 파일은 다음 형식으로 확인합니다.

```text
git grep -n -F -- "<검증할 메모 문자열>"
```

정상 상태에서는 해당 메모 문자열이 Git 최신 파일에서 검색되지 않아야 합니다.

로컬 정적 결과물은 2단계 빌드 후 `public/` 아래에서 같은 메모 문자열이 없는지 확인합니다. 실제 배포에서는 `/`, `/index.html`, `/data.json`, `/aleph.json`을 확인하며 `/data.json`은 제공되지 않아야 합니다.

반면 `/api/notes`는 2단계에서 의도적으로 공개되어 있으므로 비로그인 요청으로 가상 메모 네 건이 반환되는지 별도로 확인합니다. 검증 과정에서 서버 전용 키, 토큰 또는 실제 개인정보는 출력하거나 저장하지 않습니다.


## 3단계: Supabase Auth와 로그인 기반 자료 API

3단계에서는 Supabase Auth의 이메일·비밀번호 로그인을 사용합니다. 브라우저는 Supabase 공식 SDK로 로그인과 로그아웃을 수행하고, 로그인 후 받은 access token을 `Authorization: Bearer ...` 헤더로 자료 API에 전달합니다. 비밀번호와 access token은 코드, Git, README, 제출 묶음에 저장하지 않습니다.

서버의 자료 API는 제공된 `src/verify-login.mjs`를 수정하지 않고 사용하여 로그인 토큰을 검증합니다. 토큰이 없거나 검증에 실패한 요청은 자료를 조회하거나 입력값을 처리하기 전에 JSON 오류와 함께 거부합니다.

현재 자료 API 경로는 다음과 같습니다.

- `GET /api/notes` — 로그인한 사용자의 자료 목록 조회
- `POST /api/notes` — 새 자료 생성
- `GET /api/notes/:id` — 단일 자료 조회
- `PUT /api/notes/:id` — 자료 제목과 본문 수정
- `DELETE /api/notes/:id` — 자료 삭제

새 자료를 생성할 때 `owner_id`는 브라우저가 전달한 값을 사용하지 않고, 서버에서 검증한 로그인 사용자의 `userId`를 저장합니다. 목록 조회는 검증된 `userId`의 `owner_id`와 일치하는 자료만 반환합니다.

2단계에서 만든 네 건의 기존 가상 자료는 `owner_id`가 없는 레거시 데이터이므로 3단계 로그인 사용자의 개인 목록에는 나타나지 않습니다. 이를 특정 사용자 소유로 임의 변경하지 않습니다.

3단계에서는 인증까지만 완성하며 개별 자료의 소유권 검사는 아직 적용하지 않습니다. 따라서 로그인한 다른 사용자가 자료 ID를 알고 있는 경우 단일 조회·수정·삭제에 접근할 수 있는 상태가 남아 있으며, 이 사용자 간 자원 접근 통제는 4단계에서 해결합니다.

Supabase `notes` 테이블은 RLS를 계속 활성화하고 `anon` 및 `authenticated` 역할의 직접 테이블 접근 권한은 부여하지 않습니다. 실제 CRUD는 로그인 토큰을 검증한 Vercel 서버 함수가 서버 전용 권한으로 수행합니다.

## 4단계: 로그인 사용자별 자료 소유권 제한

4단계에서는 로그인 여부 확인에 더해, 서버가 검증한 사용자 ID와 자료의 `owner_id`를 비교하여 다른 사용자의 자료에 접근하지 못하도록 제한합니다.

기존 가상 자료는 학습용 A/B 사용자 소유로 나누어 `owner_id`를 연결했습니다. 서버는 URL이나 요청 본문의 사용자 정보를 신뢰하지 않고 `src/verify-login.mjs`가 검증한 `userId`만 소유권 판단에 사용합니다.

자료 API의 동작은 다음과 같습니다.

- `GET /api/notes` — 검증된 사용자의 `owner_id`와 일치하는 자료 목록만 반환
- `POST /api/notes` — 새 자료의 `owner_id`를 검증된 `userId`로 저장
- `GET /api/notes/:id` — 자료 ID와 `owner_id`가 모두 일치할 때만 반환
- `PUT /api/notes/:id` — 본인 소유 자료의 제목과 본문만 수정
- `DELETE /api/notes/:id` — 본인 소유 자료만 삭제

개별 자료 조회·수정·삭제는 `id`와 `owner_id`를 함께 조건으로 사용합니다. 다른 사용자가 자료 ID를 알고 요청해도 대상 행을 찾지 못한 것과 동일하게 `404` JSON 오류를 반환합니다.

서버 API는 서버 전용 Supabase 권한을 사용하므로 RLS에만 의존하지 않고 API에서 소유권을 별도로 검사합니다. 데이터베이스에도 추가 방어선으로 RLS와 최소 권한을 적용했습니다.

`public.notes`의 직접 테이블 권한은 다음과 같이 구성합니다.

- `anon` — 직접 테이블 권한 없음
- `authenticated` — `SELECT`, `INSERT`, `UPDATE`, `DELETE`
- `service_role` — 서버 API용 CRUD 권한 유지

RLS 정책은 모두 `auth.uid() = owner_id`를 기준으로 합니다.

- SELECT — 기존 행의 소유자가 본인일 때만 허용
- INSERT — 새 행의 소유자가 본인일 때만 허용
- UPDATE — 기존 행과 수정 후 행의 소유자가 모두 본인일 때만 허용
- DELETE — 기존 행의 소유자가 본인일 때만 허용

Preview에서 A/B 계정을 사용해 사용자 간 접근을 직접 확인했습니다. B 로그인 상태에서 A 소유 자료에 대한 GET·PUT·DELETE 요청은 모두 404로 거부되었고, A와 B는 각각 자신의 자료를 생성·조회·수정·삭제할 수 있었습니다.

Supabase Data API를 publishable key의 anon 역할로 직접 호출한 요청도 401과 테이블 권한 오류로 거부되는 것을 확인했습니다.

4단계 Preview에서는 `/aleph.json`의 `step` 값이 4인 것을 확인했고, 비로그인 `/api/notes` 요청은 401 JSON 오류를 반환했습니다. 첫 화면 응답의 `X-Content-Type-Options: nosniff` 보안 헤더도 유지됩니다.

로컬 회귀 확인은 다음 명령으로 실행합니다.

```text
npm run test:r5
npm run build -- --local
```

## 5단계: 자료 요청을 서버 한곳으로 모으기

5단계에서는 브라우저가 Supabase의 원본 자료 API를 직접 호출할 수 있는 경로를 차단하고, 메모 읽기·추가·수정·삭제가 Vercel 서버 함수를 통해서만 처리되도록 구성했습니다.

브라우저의 메모 관련 코드를 확인한 결과, 기존 메모 CRUD는 이미 `/api/notes` 서버 함수를 통해 수행되고 있었으며 `supabase.from(...)` 또는 Supabase REST 자료 API를 직접 호출하는 코드는 없었습니다. 따라서 제작 1에서는 메모 CRUD 코드를 별도로 변경하지 않았습니다.

4단계에서는 `authenticated` 역할에 `SELECT`, `INSERT`, `UPDATE`, `DELETE` 직접 테이블 권한이 있었기 때문에 publishable key와 로그인 토큰을 이용하면 Supabase REST API를 통해 본인 소유 메모를 직접 조회하거나 수정할 수 있었습니다. 실제 권한 회수 전 확인에서 원본 REST 조회와 수정 요청이 모두 HTTP 200으로 성공했습니다.

5단계에서는 `public.notes`에 대한 `PUBLIC`, `anon`, `authenticated`의 직접 권한을 모두 회수했습니다. 서버 함수가 사용하는 `service_role`의 CRUD 권한은 유지했습니다. 기존 RLS 소유권 정책과 서버 API의 로그인·소유자 검사는 그대로 유지했습니다.

현재 직접 테이블 권한은 다음과 같습니다.

- `anon` → 직접 CRUD 권한 없음
- `authenticated` → 직접 CRUD 권한 없음
- `service_role` → `SELECT`, `INSERT`, `UPDATE`, `DELETE`

권한 회수 후 같은 원본 Supabase REST 요청을 다시 확인했습니다.

- publishable key + 로그인 토큰 직접 조회 → HTTP 403, `permission denied for table notes`
- publishable key + 로그인 토큰 직접 수정 → HTTP 403, `permission denied for table notes`
- publishable key만 사용한 직접 조회 → HTTP 401, `permission denied for table notes`

서버 함수 경로는 권한 회수 뒤에도 정상 동작했습니다. A 계정은 자신의 메모 조회·생성·수정·삭제가 모두 가능했고, B 계정에서는 B 소유 자료만 표시되었습니다. B가 A 소유 메모를 직접 조회한 요청은 404 JSON 오류로 거부되었고, 인증 없는 `/api/notes` 요청은 401 JSON 오류로 거부되었습니다.

브라우저 화면 코드에서 Supabase 공개키를 제거하기 위해 로그인 처리도 서버 함수로 이동했습니다.

- `POST /api/auth` → 이메일·비밀번호 로그인
- `PUT /api/auth` → 세션 갱신
- `DELETE /api/auth` → 로그아웃

브라우저에서는 Supabase SDK와 Supabase 프로젝트 URL, publishable key를 사용하지 않습니다. 로그인 후 받은 access token만 메모 API의 `Authorization: Bearer ...` 헤더에 사용하며, refresh token은 JavaScript에 노출하지 않고 HttpOnly·Secure 쿠키에 저장합니다.

새 인증 구조에서도 다음 동작을 Preview에서 확인했습니다.

- A 로그인 성공
- 새로고침 후 로그인 상태 복구
- A 메모 조회·생성·수정·삭제 정상
- 로그아웃 정상
- 로그아웃 후 새로고침해도 로그아웃 상태 유지

`aleph.config.json`의 `originalApiUrl`에는 쿼리가 없는 원본 자료 API 주소를 기록했습니다. `/aleph.json`에는 현재 서버에서 사용하는 다음 8개 `allowedRoutes`가 출력됩니다.

- `POST /api/auth`
- `PUT /api/auth`
- `DELETE /api/auth`
- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

Preview 첫 화면 응답에서 `X-Content-Type-Options: nosniff`가 유지되는 것을 확인했습니다. 배포된 화면 소스에서도 Supabase publishable key, Supabase 프로젝트 주소, Supabase JS SDK 문자열이 존재하지 않는 것을 확인했습니다.

로컬 검증은 다음 명령으로 수행했습니다.

```text
node --check api\auth\index.js
npm run test:r5
npm run build -- --local
git diff --check
```

`npm run test:r5`는 6개 테스트가 모두 통과했고, 로컬 빌드도 정상 완료되었습니다.

## 보너스 XDR-01: 1차 심판 피드백 대응 (2026-10-12)

기존 1~5단계 로그인·자료 기능은 보존하고 `bonus-xdr-01-fix` 브랜치에서 분류를 보완했습니다.

**확인된 1차 실패 원인**: 처음에는 공식 형태의 `xdr/fixtures/brute-force.json` 없이 9건짜리 합성 예제로만 작업했습니다. 그래서 `result.json`의 분류 건수가 심판 요구와 맞지 않았고, `decide(alert)`는 실제 수업용 경보의 `rule.mitre: ["T1110"]`, `data.count: "48"`, `data.accounts`, 한국어 공격·정상 설명을 처리하지 못했습니다.

**시험 데이터 출처**: `xdr/fixtures/brute-force.json`은 이후 공식 시작 틀 `ChoiTimo/aleph-defense-starter`의 원본과 파일 해시가 동일함을 확인했습니다. 28건 모두 문서용 주소·가상 계정을 사용합니다. 원본을 수정하지 않았지만, 심판의 비공개 정답표와 동일하다는 보장은 없습니다. `xdr/fixtures/brute-force.demo.json`은 기존 합성 9건 예제로 별도 유지합니다.

- `read-alerts.mjs`: 필수 다섯 개 필드만 추출.
- `patterns.json`: MITRE ATT&CK T1110.001 / T1110.003 및 공격 강도별 판단 근거.
- `decide.mjs`: 단일 경보의 레벨, MITRE 태그, 실패 건수, 여러 계정 정황, 사건 설명을 이용해 독립 판단. **import/파일 I/O/외부 조회 없음**.
- `respond.mjs`: 근거 경보 ID와 15분 만료를 가진 **로컬 임시** 차단 규칙을 기록하고 알림을 `xdr/alerts.log`에 줄별 저장.
- `scripts/xdr-run.mjs`: 공식 시작 틀과 SHA가 같은 원본 실행기를 유지합니다. `aleph.xdr.result.v1` 형식의 `decisions` 및 `counts`만 출력합니다.

**재현**

```sh
npm run xdr:test
npm run xdr:run -- brute-force
npm run test:r5
npm run build -- --local
```

수업용 경보 **28건**의 기대 분류는 `block 10 / alert 9 / record 9`입니다. 과거의 9건 합성 예제는 `npm run xdr:test`의 별도 테스트에서 계속 검증합니다. 공식 실행기는 `--fixture` 인자를 지원하지 않으므로 원본 경보 파일을 교체해 실행하지 않습니다. 실제 공식 심판 판정이 아닌 로컬 검증입니다.

**운영 연결 한계**: 기존 `src/decider.mjs` 요청 계약에는 신뢰 가능한 출발 IP가 없어 XDR 로컬 차단 규칙이 실제 ZTNA 접근 차단으로 이어지지 않습니다. 운영 측의 신뢰 IP 연계와 등록된 거부 응답 코드가 필요합니다. 경보 로그와 임시 거부 규칙은 `.gitignore`로 Git 추적에서 제외합니다.

## 보너스 XDR-02: 웹 입력 조작 탐지

`bonus-xdr-02-web-injection` 브랜치에 기존 XDR-01 및 방어전 1~5단계 코드를 보존하면서 웹 입력 조작 탐지를 추가했습니다.

- `xdr/fixtures/web-injection.json`: 공식 시작 틀의 수업용 Wazuh 경보 26건을 그대로 복원했습니다. 파일 SHA가 공식 원본과 일치합니다. **심판의 비공개 정답표는 아닙니다.**
- `xdr/web-injection/read-alerts.mjs`: 시각, 출발 주소, 요청 URL, 규칙 수준, 설명의 다섯 필드를 경보마다 추출합니다.
- `xdr/web-injection/patterns.json`: MITRE ATT&CK T1190 관련 반복 SQL·스크립트 삽입·경로 이탈·명령 구분자와 단발성 의심 요청을 구분합니다.
- `xdr/web-injection/decide.mjs`: 단일 경보를 독립적으로 판단해 `{action, confidence, reason}`을 반환합니다. 파일 읽기, 외부 연결, 다른 모듈 import는 없습니다.
- `xdr/web-injection/respond.mjs`: block 후보에 임시 15분 만료와 경보 ID를 붙여 **로컬 거부 규칙**으로 저장하고, block/alert 경보를 `xdr/alerts.log`에 민감한 URL 원문 없이 줄별 기록합니다.
- `scripts/xdr-run.mjs`: XDR-01과 XDR-02에 공통으로 쓰는 **공식 시작 틀 원본 실행기**입니다. 모듈별 `decisions`와 `counts`를 생성합니다.
- `scripts/xdr-run-web-injection.mjs`: 응답 규칙·로그 로컬 테스트용 보조 실행기이며 **공식 제출 실행기는 아닙니다.**
- `test/xdr-web-injection.test.mjs`: 26건 분류 및 오탐·만료·로그·규격 회귀 검증.

```sh
npm run xdr:test
npm run xdr:run -- web-injection
npm run test:r5
npm run build -- --local
```

수업용 경보 26건에서 예상되는 분류는 `block 8 / alert 9 / record 9`입니다. 실제로 재실행하기 전에는 성공했다고 판단하지 않습니다. 이전 `npm run xdr:run -- brute-force`는 기존 구현을 그대로 사용합니다.

**중요한 제약:** 이 응답 모듈은 실제 WAF·ZTNA와 연결되어 있지 않습니다. 기존 판정기에 신뢰 가능한 요청 출발 주소가 제공되지 않으므로, 차단 동작은 로컬 규칙과 만료 검증까지만 확인합니다. 수업용 고정 경보에서의 분류 결과는 실서비스의 실제 탐지 성능이나 공식 심판 통과를 증명하지 않습니다.

### 공식 시작 틀 누락 복원 (2026-10-12)

강사 안내에 따라 원본 `xdr/README.md`의 **심판 격리 환경에서 지킬 것**, `scripts/xdr-run.mjs`를 공식 시작 틀과 동일한 내용으로 복원했습니다. `xdr/fixtures/`의 여섯 파일도 원본과 SHA가 모두 같습니다. 1차 보너스 XDR-01의 `decide.mjs`, `patterns.json`, `result.json` 및 기존 1~5단계 기능은 수정하지 않았습니다. 남은 보너스의 격리 심판은 각 `decide.mjs` 한 파일만 로드하므로 import·파일 접근·네트워크 호출 없이 경보마다 독립적으로 판단합니다. 패키징 단계의 `package/`와 `api/` 관련 원본 파일은 그 단계에 도달한 뒤 검토하며 지금은 복원하지 않습니다.


## 6단계: 등록한 기기만 자료실에 들어옵니다

### 구현 목적

등록된 기기의 요청만 허용하고, 미등록 기기나 등록 여부를 확인할 수 없는 요청은 거부한다.

이번 단계에서는 별도의 접속 프로그램을 설치하거나 인증서를 발급하지 않는다. 공식 판정 요청 계약에 따라 `src/decider.mjs`에 기기 등록 조건을 구현한다.

### 구현 내용

- `docs/DECIDER_REQUEST.md`의 `aleph.decision.v1` 계약을 기준으로 작성
- `RULE_IDS`에 `device_registered` 규칙 등록
- `request.deviceRegistered === true`이면 `allow`, `approved` 반환
- `deviceRegistered`가 `false`이거나 없으면 `deny`, `device_not_registered` 반환
- 판정 응답의 필드 5개 유지
- 기존 자료실 API, 로그인 및 데이터베이스 기능 유지
- 인증서, CA, 개인키 및 서명 키를 새로 생성하거나 저장하지 않음

### 검증 방법

다음 명령어로 기존 기능과 판정 규칙을 검증한다.

```cmd
node --check src\decider.mjs
npm run decider:test
npm run test:r5
```

### 로컬 검증 결과

- JavaScript 문법 검사 통과
- 등록 기기의 정상 요청: 통과 (`allow`)
- 미등록 기기의 가상 요청: 통과 (`deny`, `device_not_registered`)
- 기존 기능 회귀 테스트: 8개 통과

`npm run decider:test`는 공식 엔진이 아닌 로컬 가상 요청 테스트다. 실제 공격 차단 및 공식 심판 통과 여부는 별도로 확인한다.

### 기존 자료실 유지

기존 1~5단계 기능은 수정하지 않았다. 6단계 Preview에서 기존 시험 계정으로 로그인하고 메모를 정상 조회한 것을 확인했다.

이는 기존 화면의 기능 유지 확인이며, 실제 기기 등록 여부를 검증한 결과는 아니다.

### 제출 전 확인

- [x] 기기 등록 판정 규칙 구현
- [x] 로컬 판정 테스트 통과
- [x] 기존 기능 회귀 테스트 통과
- [x] 개인키 및 인증서 신규 생성 없음
- [x] 최종 커밋 및 배포 확인
- [x] 공식 심판 제출 및 결과 확인 (2026-10-13, 6단계 통과)


## 7단계: 평소와 다른 접속은 다시 확인합니다 (2026-10-13)

### 구현 및 판정 범위

- `docs/DECIDER_REQUEST.md`의 검증된 요청 계약만 사용하고, 브라우저가 임의로 지정한 위치·네트워크 헤더는 사용하지 않습니다.
- `src/decider.mjs`에서 `device_registered`를 유지하고 `step_up_required` 규칙을 추가했습니다. 등록되지 않은 기기는 먼저 `deny/device_not_registered`로 거부합니다.
- `signals.source === 'judge_fixture'`이고 지역·네트워크·시각·최근 사건의 형식이 유효한 가상 요청에서만 신호를 판정합니다. `source: 'none'`, 필드 누락, `unknown` 값은 임의의 정상 위치로 바꾸지 않습니다.
- 낯선 네트워크(`unusual`), 평소와 다른 시각(22~05시), 최근 300초 이내 대량 위험 사건(`risk_signal`, count >= 10)이 **동시에** 나타나면 `step_up/step_up_required`를 반환합니다. 지역 변화 하나만으로 영구 차단하지 않습니다.
- 엔진이 전달한 `stepUp.verified === true`와 `authAgeSeconds`가 0~300초인 가상 재확인 요청은 `allow`로 판정합니다. 값의 유효성만 판정하며 실제 재로그인을 자체 구현하거나 토큰을 저장하지 않습니다.

### 재현 및 검증

```sh
node --check src/decider.mjs
npm run fixture:7
npm run decider:test
npm run test:r5
npm run build -- --local
npm run bundle
```

2026-10-13 로컬 확인: `fixture:7` 정상 요청 `allow`, 복합 이상 요청 `step_up`; `decider:test` 4건 통과; 기존 `test:r5` 8건 통과. 7단계 빌드·회귀 테스트는 저장점 이후 재실행할 예정입니다.

### 제작 3 계약 점검 및 미실행 범위

- 공식 `docs/DECIDER_REQUEST.md`에는 `stepUp.verified`, `stepUp.authAgeSeconds`가 있습니다. 다만 동일한 사용자의 **새 로그인 시각을 엔진이 어떻게 검증해 재요청에 반영하는지**를 확인할 수 있는 구현은 현재 공개된 학생 저장소/공식 시작 틀에서 확인하지 못했습니다.
- 가상 요청에서 추가 확인 전 `step_up` 및 확인 후 `allow`는 재현했습니다. 실제 운영 연결에서 재로그인 전 자료 차단, 동일 사용자 새 로그인 후 자료 조회 재개는 **미실행**입니다. 자료실 API를 임의 수정하거나 토큰 원문을 기록하지 않았습니다.
- `src/attack-check.mjs`의 HTTP 점검은 공개 파일 부재와 비인증 API 차단만 실측하며, 운영 엔진의 추가 인증이 성공했다고 주장하지 않습니다. 공식 심판 판정은 별도로 확인해야 합니다.

### 진행 상태

- [x] 제작 1: 접속 신호 출처·형식 검사
- [x] 제작 2: 복합 이상 가상 접속 추가 확인 판정
- [x] 제작 3: 계약 확인, 미검증 운영 연계 명시
- [x] 7단계 배포 확인 및 공식 심판 통과 확인 (2026-10-13)

## 8단계: 메모 소유권·강사 공지 자원 구역 (2026-10-13)

### 동작 및 적용 범위

- 메모 API는 검증된 로그인 주체의 `userId`와 DB의 `notes.owner_id`를 함께 확인합니다. 목록·개별 조회·수정·삭제에서 타인 소유 메모는 노출하지 않고, 개별 요청은 `404`로 응답합니다. 브라우저에서 전달한 사용자 ID나 역할 선언은 사용하지 않습니다.
- 강사 공지는 `/api/instructor-notices`(목록 GET, 작성 POST)와 `/api/instructor-notices/:id`(조회 GET, 수정 PUT)로 구별됩니다. 서버가 로그인 토큰을 검증한 후 DB의 `instructor_memberships`를 다시 확인하여 일반 사용자의 작성·수정을 `403`으로 차단합니다. 강사 공지 조회는 로그인 사용자에게 허용합니다.
- `src/decider.mjs`의 `resource_scope`는 7단계 `/notes/demo` 연습 요청에는 엔진의 주체·기기·반·프로젝트를 비교하고, 운영 `/api/notes/:id`에는 정확한 UUID·메서드·경로만 분류합니다. **운영 UUID를 판정기가 허용하는 것은 소유권 허용이 아니므로** 자료 API가 서명 검증된 A/B 또는 학생 주체와 저장된 `owner_id`를 GET·PUT·DELETE에서 반드시 다시 비교합니다. 다른 기능 경로·쿼리·일반 학생의 공지 변경은 판정기에서 거부합니다. 공식 심판의 독립 판정기 테스트가 UUID 자체에 소유권 판단을 요구한다면 추가 계약 없이 확인 불가합니다.
- 기존 6단계 기기 등록 규칙과 7단계 가상 위험 신호 기반 추가 확인 규칙을 유지합니다. `docs/DECIDER_REQUEST.md`의 다섯 항목 응답 계약을 변경하지 않았습니다.
- DB 스키마 재현은 `supabase/step8_instructor_resource_zones.sql`에 있습니다. 새로운 테이블에 RLS를 활성화하고 직접 공개 권한을 주지 않으며, 서버 전용 역할에서만 접근합니다. 기존 메모를 변경하거나 임의의 강사 계정을 생성하지 않습니다.

### 배포 및 재현

- 개발·검증 브랜치: `step8-resource-zones`. 통과한 7단계의 커밋 이력은 유지하면서 8단계 저장점을 `main`에 반영합니다.
- 8단계 Preview: `https://choi-bujang-secret-vault-git-step8-resource-zones-yeaun.vercel.app/`
- 운영 주소: `https://choi-bujang-secret-vault-blush.vercel.app/`. `main` 반영 후 이 주소에서 실제 8단계 배포 및 비인증 점검을 확인합니다.
- `aleph.config.json`의 `judgeIssuer`, `identityProvider`, `originalApiUrl`은 이전 단계에서 검증한 값을 유지하며, `allowedRoutes`에 공지 API 네 경로를 추가했습니다.

```cmd
git switch step8-resource-zones
git pull --ff-only origin step8-resource-zones
node --test test/resource-id.test.mjs test/resource-policy.test.mjs test/resource-api-auth.test.mjs test/instructor-notices.test.mjs
npm run decider:test
npm run fixture:7
npm run test:r5
npm run build -- --local
```

메모와 강사 공지의 자료 API에서는 쿼리가 붙은 목록·단건 경로를 거부합니다. 요청자가 쿼리로 다른 소유자나 기능을 지정해도 정상 리소스 경로로 취급하지 않습니다. 이 점검은 심판 실패 원인에 대한 가설이며 실제 심판 재현으로 확인되지 않았습니다.

`npm run bundle`은 **커밋한 뒤**, 깨끗한 Git 작업 트리와 로컬 전용 `bundle-notes.json`의 `explanation`이 준비됐을 때만 실행합니다. 이 명령은 `artifacts/submission.json`을 만들면서 배포 API에 비인증 HTTP 점검을 실시합니다. 생성 파일과 `bundle-notes.json`은 커밋하지 않습니다.

### 실제 계정 및 API 검증 (2026-10-13)

- A·B 각각 본인 메모 목록 조회 `200`. B가 A의 테스트 메모에 직접 GET·PUT·DELETE 요청하면 모두 `404`. A가 다시 조회·새로고침한 결과 원본 메모가 변경되지 않았음을 확인했습니다.
- 일반 B 계정에서 강사 공지 목록 조회 `200`, 공지 작성 POST `403`, 공지 수정 PUT `403`.
- A 계정에 테스트 목적으로 강사 권한을 임시 부여하여 공지 작성 POST `201`, 수정 PUT `200`, 재조회 GET `200`, 수정 결과 일치를 확인했습니다. 검증 직후 임시 공지 1건과 임시 강사 권한 1건을 삭제·회수했습니다. 이후 확인한 DB의 강사 공지와 강사 권한 등록은 각각 0건이며 메모 5건은 유지됩니다.
- Preview 시크릿 창에서 메인 로그인 화면과 비인증 메모 API 거부를 확인했습니다. 이 확인은 사용자가 실제로 수행했으며, 로컬 판정기 테스트는 공식 심판 결과가 아닙니다.

### 미검증 사항

- 2026-10-13 공식 8단계 심판은 커밋 `22ba9421e469`에서 통과했습니다. 이 항목의 이전 미검증 기록은 통과 전 상태였습니다. 단, 엔진 reasonCode 등록부 자체는 별도로 조회하지 않았습니다.
- `src/attack-check.mjs`의 자동 점검은 비인증 공개 파일·메모·공지 경로만 검사합니다. A/B 소유권 및 강사 권한의 실제 HTTP 테스트는 수동으로 수행했으며 제출 묶음 생성 때 사용자의 로그인 토큰을 재사용하지 않습니다.

### 8단계 구역 규칙 보완 · 전체 목록 판정 거부

공식 심판 커밋 `c7507158cd5b`에서 48/100, `S08_OTHER_ZONE_ALLOWED`가 발생했고, 심판이 **판정기의 메모 전체 목록 허용이나 공지·강사 자료 쓰기 허용**을 지적했습니다. 검토 결과 판정기는 `GET /api/notes` 및 `GET /notes` 전체 목록 경로를 `allow`로 분류하고 있었습니다. 이 두 경로와 잘못된 목록 동작은 판정기에서 거부합니다. 메모 생성에 필요한 `POST /api/notes`만 유지합니다.

단건 UUID 메모는 기존처럼 경로를 정확히 검사하고 실제 소유권은 서버 API의 검증된 사용자·저장된 `owner_id` 필터에서 최종 확인합니다. 학생의 공지 쓰기 거부, 공지 읽기, 등록된 기기 검사, 7단계 가상 재인증 흐름은 변경하지 않았습니다. 실제 웹의 자기 메모 목록 조회 API도 변경하지 않았습니다. 커밋 `22ba9421e469`에서 공식 8단계 심판 통과를 확인했습니다.

## 9단계 저장점: 도플갱어 탐지 및 회수 제안 (2026-10-13)

8단계 공식 통과 커밋 `22ba9421e469`을 기반으로 9단계 탐지 함수를 구현했습니다. 기존 `src/decider.mjs`의 기기 등록·추가 인증·자원 경로 규칙, 로그인, 메모/공지 API, DB 및 XDR 보너스는 변경하지 않았습니다.

- 제작 1: 공식 로컬 사건의 `at`, `method`, `identity.sub`만 추출하고, 메모 본문·토큰·실명·임의 기기/역할 주장을 보존하거나 기록하지 않습니다.
- 제작 2: 동일 가명 사용자가 **이동하는 10분 내 GET 120건을 초과**할 때 `burst_read` 후보를 탐지합니다. 정확히 120건, 다른 사용자의 요청, POST, 시간 구간 밖 요청은 탐지하지 않습니다.
- 제작 3: 탐지되면 기존 접근 판정과 별도로 `{action:'propose_revocation',reasonCode:'burst_read',subject:'가명 사용자'}`를 반환합니다. 정상 사건은 `{action:'observe'}`입니다. 회수 API를 만들거나 세션·기기의 실제 권한을 변경하지 않습니다.

**입력 계약의 제약:** 9단계 카드에는 낯선 네트워크+대량 조회 복합 신호와 확인된 기기 하나에 대한 회수 제안이 있지만, 현재 제공된 `docs/DETECT_EVENTS.md` 및 `scripts/detect-test.mjs` 가상 사건에는 네트워크·검증된 기기 ID·판정 결과가 없습니다. 임의 필드로 기기를 결정하지 않고 로컬 공식 계약의 `identity.sub`만 결과로 반환합니다. 실제 엔진의 기기 회수, 회수 이후 세션 차단, 소요 시간과 공식 심판 통과는 아직 확인되지 않았습니다.

`aleph.config.json`의 `step`을 9로 올렸으며 기존 `judgeIssuer`, `identityProvider`, `allowedRoutes`, `originalApiUrl`, 운영 사이트 URL은 변경하지 않았습니다. 9단계도 빌드·배포 식별·기존 비인증 HTTP 자기 점검을 지원합니다. 자기 점검 6건은 **실제로 보낸 HTTP 요청**만 기록하고, 가상 탐지 결과를 HTTP 방어 성공으로 표현하지 않습니다.

### 재현 및 제출

```cmd
node --test test/stage9-detect-input.test.mjs test/stage9-burst-rule.test.mjs test/stage9-proposal.test.mjs
npm run detect:test
npm run decider:test
npm run fixture:7
npm run test:r5
npm run build -- --local
git status --short
```

제작 1~3의 로컬 탐지 테스트 11/11, `detect:test` 6/6, 기존 회귀 테스트 12/12는 저장점 직전 사용자 CMD에서 확인했습니다. 이번 설정·빌드 지원 변경 이후의 재검증은 별도로 필요합니다.

`bundle-notes.json`은 Git에서 제외되는 로컬 파일이며 최소 `explanation` 10자 이상이 필요합니다. 커밋 반영 후 `npm run bundle`은 실측된 비인증 HTTP 결과와 커밋 정보를 `artifacts/submission.json`에 기록합니다. 두 JSON은 Git에 커밋하지 않습니다.


## 10단계 제작 3: 시험 계정 B의 비공개 메모 사본 및 복구 경로

- 서비스: 기존 메모 자료실 Vercel 서버리스 API. 복구 경로: **`POST /api/restore`** (`aleph.config.json.restoreRoute = "/api/restore"`). JSON 본문은 `{"noteId":"<복구할 한 건의 UUID>"}`이며 `id` 별칭도 허용합니다.
- 인증: 서버가 `createLoginVerifier`로 검증한 공식 심판의 B 가상 신원(`kind=judge`, `identity=b`, 서명 검증된 run ID)만 허용합니다. 일반 학생·심판 A·익명 사용자는 복원할 수 없습니다. 토큰·메모 본문은 로그·GitHub·제출 묶음에 기록하지 않습니다.
- 백업 확보: `POST /api/notes`가 **새로운 시험 B 메모를 최초 생성할 때만** 동일 실행·소유자의 제목·본문·원래 생성 시각을 비공개 `stage10_note_backups`에 INSERT합니다. 해시는 UTF-8 메모 본문 SHA-256입니다. 백업 기본키 `(judge_run_id, note_id)`로 덮어쓰기를 차단합니다. `GET`, `PUT` 또는 사고 후 복원 요청으로 변조된 데이터를 새 백업으로 저장하지 않습니다.
- 복구: B의 POST 복구 요청 → 복구 감사 요청 기록 → 같은 실행·같은 ID·같은 소유자의 사본 조회 → 해시 검증 → 기존 메모가 있다면 소유자 일치 확인 후 해당 한 건 수정, 삭제된 메모라면 동일 ID로 생성 → 복구 후 ID·소유자·제목·본문 해시 재검증 → 감사 완료 기록. 사본 없음·해시 불일치·타인 소유자 충돌이면 복원을 중단합니다.
- 기존 메모·강사 공지·다른 서비스·감사 기록은 초기화/전체 복원하지 않습니다. `stage10_restore_audit`는 메모 내용 없이 사건 종류와 이유·해시만 추가합니다.

**검증 경계:** 비공개 DB 사본은 새 시험 B 메모의 최초 생성 시점에만 저장됩니다. 이 기능의 배포 전에 이미 존재한 메모나 공식 심판이 API 외부에서 직접 만든 메모에는 사전 사본이 없습니다. SHA-256만으로 사본이 침해 이전이라는 점을 증명하지는 못하며, 최초 생성 흐름과 공식 심판 순서를 확인해야 합니다. DB 작업이 연속된 여러 요청으로 처리되므로 동시 쓰기까지 완전한 단일 트랜잭션으로 보장하지는 않습니다.

```cmd
node --test test/stage10-recovery.test.mjs
node --check api/restore.js
node --check api/notes/index.js
npm run decider:test
npm run fixture:7
npm run test:r5
```

로컬 테스트는 합성 가상 B 메모로만 수행합니다. 운영 B 토큰은 복사·출력하지 않습니다. 공식 B 메모의 실제 변조·삭제 후 복구, 1~9단계 전체 재평가와 심판 판정은 **미실행**입니다.


## 10단계 제작 4: 복구 후 1~9단계 재검증 순서

**실행 조건:** 실제 공식 시험 계정 B의 **침해 전 검증된 사본**에서 변조·삭제된 대상 **한 건만** 복원하고, ID·소유자·본문 SHA-256 일치를 확인합니다. 사전 사본 없거나 출처·해시 검증 실패 시 복원을 중단합니다. 아래 가상 테스트 결과는 운영 복구 뒤 실제 재시험으로 대체할 수 없습니다.

1. **10단계 복원과 감사:** 같은 심판 실행(run)의 B 메모 최초 백업 존재 확인 → 변조/삭제 → `POST /api/restore`에 서명 검증된 B와 `noteId` 하나만 전달 → 백업과 동일한 `id`, `owner_id`, 본문 SHA-256 및 정상 메모 수·감사 이력 보존 확인. 사본 누락·다른 ID/소유자·해시 불일치·시험 A/익명/학생 신원은 거부.
2. **1~2단계 정적 유출 방지:** 비인증 `GET /data.json`은 404이며 초기 공개 가상 자료가 다시 노출되지 않는지 확인.
3. **3단계 인증:** 비인증 `GET /api/notes`, `POST /api/notes`, 잘못된 로그인 토큰 요청은 401/403으로 거부; 본인 로그인 후 본인 메모 목록은 유지.
4. **4~5단계 소유권/서버 경로:** 정상 A의 자기 메모 `GET` 유지, B의 A 메모 `GET`/`PUT`/`DELETE`는 404. 역할·소유자 주장 또는 쿼리로 우회 불가. 다른 메모 원본 불변.
5. **6단계 기기:** 등록 기기 가상 요청은 `allow`; 미등록 기기는 `deny/device_not_registered`.
6. **7단계 추가 인증:** 정상 사건 `allow`; 낯선 네트워크·비정상 시간·최근 위험 사건이 모두 겹친 가상 요청 `step_up`; 후속 검증된 요청만 재허용.
7. **8단계 자원 구역:** 학생 강사 공지 조회는 유지, 공지 작성·수정 거부. 판정기의 전체 목록 허용·기능 경로·역할 위조는 거부.
8. **9단계 이상 조회:** 10분 내 단일 가명 사용자 GET 120건 `observe`, 121건 `propose_revocation/burst_read`; 다른 사용자·시간대 혼합 금지. 실제 세션 회수는 공식 엔진 평가.

### 재검증 명령

```cmd
node --test test/stage10-policy-diff.test.mjs test/stage10-policy-restore.test.mjs test/stage10-recovery.test.mjs
node --test test/resource-id.test.mjs test/resource-policy.test.mjs test/resource-api-auth.test.mjs test/instructor-notices.test.mjs
node --test test/stage9-detect-input.test.mjs test/stage9-burst-rule.test.mjs test/stage9-proposal.test.mjs
npm run detect:test
npm run decider:test
npm run fixture:7
npm run test:r5
npm run build -- --local
git status --short
```

**이미 확인한 로컬 결과:** 사용자 CMD로 10단계 정책 복원 8/8, 가상 메모 복원 5/5, 자원 접근 통제 16/16, 판정기 4건, 탐지 6건, 7단계 allow/step_up, R5 회귀 14/14, 로컬 빌드 성공. 이 검증은 **실제 B 메모 복구 후 실행한 테스트가 아닙니다**.

**미실행:** 공식 B 메모 백업 생성 → 실제 변조·삭제 → POST 복원 → 원본 해시·소유자 대조; 실제 A/B 세션의 정상/거부 요청 재검증; 공식 심판의 1~9단계 공격 재전송. 명시적으로 미실행으로 유지하고 결과를 추정하지 않습니다.

**보존:** 기존 1~9단계 `decide(request)` 다섯 필드·`RULE_IDS` 세 개, `src/detect.mjs`, 메모·공지 DB, 기존 감사 기록. `judgeIssuer`와 서버 전용 비밀값을 변경하거나 공개하지 않습니다. 제출 묶음에는 비공개 메모 본문을 포함하지 않습니다.
