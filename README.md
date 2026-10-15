# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 시작 당시에는 `/data.json`에서 가상 메모가 공개되었습니다. Production 1부터 이 정적 파일에는 메모를 두지 않습니다. 현재 `/` 화면은 Supabase Auth 이메일 로그인·로그아웃을 제공하고, 세션의 Bearer 토큰을 `/api/notes`에 보냅니다. 서버 함수는 `src/verify-login.mjs`로 토큰을 검증한 뒤 Supabase `training_notes`를 조회합니다. 메모 추가·수정·삭제는 로그인한 사용자만 요청할 수 있습니다.

## Production 2 환경 설정

Vercel 프로젝트의 **Settings → Environment Variables**에서 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 서버 환경변수로 설정하세요. 실제 값은 Vercel의 비밀 입력란에서 직접 입력하고 코드나 브라우저 환경변수에 넣지 않습니다. 저장 후 새 배포를 실행합니다. 서버 비밀 키는 API 함수에서만 사용하며 응답하지 않습니다.

## 3단계 제작 1~3

로그인 사용자는 자료실 화면에서 메모를 추가·수정·삭제할 수 있습니다. 목록은 검증된 로그인 사용자의 `owner_id`로 조회하며, 새 메모의 소유자 ID는 서버가 토큰에서 확인해 저장합니다. 당시 단건 `GET`, `PUT`, `DELETE`에는 소유자 검사가 없었으며, 이 검사는 4단계 제작 2에서 추가했습니다.

Supabase SQL Editor에서 `sql/production-3-notes-uuid.sql`을 실행해 기존 bigint 기본 키를 유지하면서 API 메모 UUID 열을 추가했습니다. 이 마이그레이션은 기존 가상 메모 데이터를 변경하거나 삭제하지 않습니다.

## 4단계 제작 1~3

제작 1에서는 기존 가상 메모 세 건을 A 사용자 UUID에 연결하고, B 사용자 소유의 공개 가능한 시험 메모 한 건을 추가했습니다. 나머지 기존 데이터는 보존했습니다. UUID는 Supabase `auth.users`에서 이메일로 조회해 사용했습니다.

제작 2에서는 API가 토큰 검증으로 얻은 `userId`를 소유자 기준으로 사용합니다. 목록 조회는 본인 소유 메모만 반환하고, 메모 추가 시 `owner_id`를 검증된 `userId`로 저장합니다. 단건 `GET`, `PUT`, `DELETE`는 `note_uuid`와 검증된 `userId`를 함께 확인하며, 타인 소유 메모에는 `404`를 반환합니다. `PUT` 본문에서 `owner_id`를 지정하면 요청을 거부합니다.

저장소의 `sql/production-1-training-notes.sql`은 `public.training_notes`에 RLS를 활성화하고 `anon`, `authenticated`의 테이블·시퀀스 권한을 회수합니다. `sql/production-3-notes-uuid.sql`은 API용 UUID 열과 인덱스를 추가합니다. 이 저장소에서 `authenticated`용 소유자 정책을 만드는 SQL이나 실제 Supabase 적용 내역은 확인되지 않으므로, DB의 현재 권한 상태는 별도로 확인해야 합니다.

## 5단계 · 자료 요청을 서버 한곳으로 모으기

브라우저의 메모 목록·추가 요청은 `/api/notes` Vercel 함수로, 단건 조회·수정·삭제 요청은 `/api/notes/:id` 함수로 보냅니다. 브라우저의 Supabase Auth 로그인·로그아웃은 유지합니다. 서버 함수는 Bearer 세션을 검증하고, 검증된 `userId`를 소유자 조건으로 사용합니다. 단건 조회·수정·삭제도 `note_uuid`와 `owner_id`를 함께 확인합니다. 서버 함수의 실제 DB 연결에는 Vercel의 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수가 필요합니다.

`aleph.config.json`은 5단계를 가리킵니다. `originalApiUrl`은 쿼리 문자열이 없는 HTTPS 원본 자료 API 주소이며, `allowedRoutes`는 구현된 목록·추가·단건 조회·수정·삭제 경로와 일치합니다. `judgeIssuer`와 Production `publicAppUrl`은 기존 값을 유지합니다. SQL 파일의 존재만으로 Supabase 프로젝트에 실제 적용됐는지는 확인할 수 없습니다.

`vercel.json`에는 현재 `/` 응답에 `X-Content-Type-Options: nosniff` 헤더가 설정되어 있습니다. API 경로 전체에 적용되는 별도 보안 헤더 설정은 없습니다.

로컬 관련 검사는 `npm run test:r5`와 `npm run build -- --local`입니다. 제출 묶음은 저장 설정을 커밋한 뒤 깨끗한 Git 작업 트리에서 `npm run bundle`로 생성합니다. 자기 점검은 실제 배포 주소의 무로그인 `GET /api/notes` 요청을 보내 관찰 결과를 기록하며 심판 판정은 아닙니다. A/B 계정의 CRUD 확인은 별도의 실제 배포·Supabase 환경 점검입니다.

로컬 정적 빌드는 `npm run build -- --local`로 확인합니다. 제출 자료 생성은 Git 작업 트리가 깨끗하고 저장 설정이 커밋된 상태에서 `npm run bundle`을 실행합니다. bundle은 실제 배포에 보낸 무로그인 요청의 관찰 결과만 자체 점검으로 기록하며, 실제 심판 판정으로 간주하지 않습니다.

## 6단계 · 등록 기기 판정

`src/decider.mjs`는 엔진이 확인해 전달한 `deviceRegistered`가 `true`일 때 요청을 `allow`하고, `false`이거나 값이 없으면 `deny`와 `device_not_registered`를 반환합니다. 등록 여부는 브라우저 입력이 아니라 반 엔진이 확인한 계약 값입니다. 요청·응답 필드는 [docs/DECIDER_REQUEST.md](docs/DECIDER_REQUEST.md)의 `aleph.decision.v1` 계약을 따릅니다.

로컬 가상 요청 확인은 저장소 루트에서 `npm run decider:test`를 실행합니다. 출력에서 `등록 기기의 정상 요청`은 통과하고 `미등록 기기의 가상 요청`은 `deny` 및 `device_not_registered`여야 합니다. 별도 접속 프로그램 설치는 필요하지 않습니다. 이 연습은 로컬 가상 요청 결과이며 실제 심판 판정이나 미등록 기기의 운영 접속 시험이 아닙니다.

## 7단계 · 평소와 다른 접속은 다시 확인합니다

`src/decider.mjs`는 계약의 `signals`와 `recentEvents`만 검사합니다. 등록 기기에서 정수 시각 21~23시 또는 0~7시, 로컬 정책상 낯선 네트워크 값, 최근 300초 안의 읽기 관련 사건 수 합계 8 이상이 모두 충족되면 `step_up`을 반환합니다. 네트워크 분류 문자열과 시간·횟수 기준은 계약이 정한 심판 기준이 아니라 fixture와 저장소를 바탕으로 둔 로컬 정책입니다. 이전의 네트워크·사건 종류 정확한 문자열 비교에서 벗어나 `first-seen`, `new network`, `unfamiliar`와 `file-access`, `mass_read`, `note_read` 같은 명시적 표현도 보수적으로 정규화해 판단합니다. 지정되지 않은 표현은 여전히 정보 불충분으로 처리합니다. `risk_signal`은 fixture용 가상 위험 대리 사건이며 실제 파일 읽기 증거가 아닙니다. 정상 등록 기기는 `allow`, 미등록 또는 등록 미확인 기기는 기존 `deny`입니다. `source`는 출처 메타데이터이며 네 번째 이상 조건으로 쓰지 않습니다. `judge_fixture`도 실제 위치·네트워크 증거가 아닙니다.

현재 `docs/DECIDER_REQUEST.md`에는 추가 확인 후 같은 로그인 주체의 재로그인 시각과 전후 요청 연결을 검증하는 계약이 없습니다. 따라서 실제 추가 확인 전 자료 차단과 새 로그인 후 허용은 미구현입니다. 자료 API의 기존 Bearer 로그인·소유자 검사는 유지됩니다. `npm run fixture:7`, `npm run decider:test`, `npm test`는 로컬 가상 요청 및 저장소 테스트이며 심판 판정이나 실제 재로그인 검증이 아닙니다. 원래 제공된 `scripts/decider-test.mjs`는 `stepUp.verified: true`의 가상 요청에 `allow`를 기대합니다. 그러나 `docs/DECIDER_REQUEST.md`는 이 정보만으로 재인증 요청을 건너뛰지 말라고 명시하며 요청 간 검증 연결도 제공하지 않습니다. 따라서 테스트의 기대값을 `step_up`으로 바꾸어 성공을 가장하지 않고 원본 `allow` 기대값을 유지합니다. 로컬 재확인 가상 검사는 실패 사실을 그대로 남기며, 실제 엔진 기반 재로그인 검증은 **미실행·미검증**입니다. 이 제한은 CI 실행 요약에도 명시하고 `stepUp.verified`만으로 `allow`하지 않습니다.

`npm run bundle`의 7단계 학생 자기 점검은 실제 배포 주소에 무로그인 `GET /api/notes`를 보내 관찰 결과를 기록합니다. 이 자체 점검은 심판 판정이나 추가 확인 기능의 실측이 아닙니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. `publicAppUrl`에는 고정된 Production URL을 기록합니다. 필요한 배포 식별 정보가 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`에는 현재 저장소 주소와 고정된 Production `publicAppUrl`이 설정되어 있습니다. 1단계에서는 학생이 이 파일을 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 정적 화면을 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 Supabase 연결을 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/api/notes`의 응답을 확인합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 보너스 XDR: 무차별 로그인 공격 연습

`xdr/fixtures/brute-force.json`은 가상 Wazuh 모양 경보입니다. `xdr/brute-force/decide.mjs`는 경보를 `block`, `alert`, `record`로 분류하고, `npm run xdr:run -- brute-force` 또는 `npm run xdr -- brute-force`가 결과를 `xdr/brute-force/result.json`에 씁니다. 다시 실행해 결과를 갱신할 수 있습니다.

`xdr/brute-force/respond.mjs`는 `block` 판단만 만료 시각과 경보 번호가 붙은 `deny-rules.json` 후보로 만들고, 차단·알림 판단을 `xdr/alerts.log`에 한 줄씩 덧붙입니다. 이 후보 파일은 연습 자료이며, 현재 ZTNA 판정기 `src/decider.mjs`에 자동 적용되지는 않습니다. XDR 실행 결과는 가상 경보 연습이지 운영 차단이나 심판 판정의 증거가 아닙니다.
