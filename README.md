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

Preview 첫 화면 응답에서 `X-Content-Type-Options: nosniff`가 유지되는 것을 확인했습니다. 배포된 화면 소스에서도 `sb_publishable_`, `supabase.co`, `supabase-js` 문자열이 존재하지 않는 것을 확인했습니다.

로컬 검증은 다음 명령으로 수행했습니다.

```text
node --check api\auth\index.js
npm run test:r5
npm run build -- --local
git diff --check
```

`npm run test:r5`는 6개 테스트가 모두 통과했고, 로컬 빌드도 정상 완료되었습니다.
