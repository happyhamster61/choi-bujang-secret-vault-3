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

심판의 7단계 추가 안내에 따라 엔진이 검증해 전달한 `stepUp.verified === true`와 `authAgeSeconds`가 정수 0~300초인 경우에만 복합 이상 요청의 추가 확인을 통과시켜 등록 기기 규칙에 따릅니다. 301초 이상이거나 미확인·누락·잘못된 값이면 `step_up`을 유지하고, 미등록 기기는 언제나 `deny`입니다. 클라이언트가 제공한 임의 확인값을 신뢰하지 않으며, 판정기는 계약에 없는 요청 필드를 생성하지 않습니다. `npm run fixture:7`, `npm run decider:test`, `npm test`는 로컬 가상 요청 및 저장소 테스트입니다. 공개 엔진 계약에는 동일 로그인 주체의 새 로그인 시각과 요청 연결을 별도로 실측할 자료가 없어 **실제 자료 차단·재로그인 후 허용의 종단 간 실측은 미실행**입니다. 로컬 4개 가상 판정은 정상·미등록·복합 이상·엔진 확인 후 허용을 각각 확인합니다.

`npm run bundle`의 7단계 학생 자기 점검은 실제 배포 주소에 무로그인 `GET /api/notes`를 보내 관찰 결과를 기록합니다. 이 자체 점검은 심판 판정이나 추가 확인 기능의 실측이 아닙니다.

## 8단계 · 자료마다 갈 수 있는 구역을 나눕니다

- 등록 기기·복합 이상 시간/네트워크/읽기 사건·5분 이내 엔진 추가 확인을 유지하면서, `src/decider.mjs`는 엔진이 제공한 `service`, `method`, `route`, `path`를 함께 확인합니다. 메모는 단건 ID 경로의 GET/PUT/DELETE만 허용합니다. `/notes` 전체 목록, 기능형 `/notes/export`, 구역 불명 요청은 거부하며 가상 ID를 UUID로 제한하지 않습니다. 반 공지는 단건 GET만 가능하고 POST/PUT/PATCH/DELETE는 거부합니다. 강사 자료는 학생 판정기에서 언제나 거부합니다.
- `aleph.config.json`은 8단계이며 정확한 허용 경로만 포함합니다. 기존 `/api/notes`의 자체 소유자별 목록·새 메모 생성은 레거시 UI용으로 유지하지만, 엔진의 학생 정책에는 등록하지 않습니다.
- 메모 원본은 기존 `training_notes.note_uuid`와 `owner_id`를 보존하고 서버에서 확인합니다. 새 반 공지와 강사 자료는 `training_zone_resources`의 별도 `resource_id`, `zone`, `class_id`로 구분합니다. 반 공지 조회 시 서버는 `training_class_memberships`의 동일 반 소속 여부를 확인합니다. 공지 수정은 학생 판정기의 허용 경로 밖의 `/api/admin/class-announcements/:id`에서만 관리하며, 서버에 저장된 `instructor` 역할을 확인합니다. 요청 본문의 `role`은 신뢰하지 않습니다.
- `sql/production-8-resource-zones.sql`은 연결된 Supabase 운영 프로젝트에 `stage8_resource_zones` 마이그레이션으로 적용했습니다. 기존 메모 6건은 보존됐고, 신규 두 테이블의 RLS 활성화 및 `anon`·`authenticated` 직접 권한 없음도 확인했습니다. 반 소속과 구역 자료 테이블은 빈 상태입니다. 8단계 지침은 임의 학생·강사 계정 생성이나 강사 권한 부여를 요구하지 않으므로 실제 신원 확인 없이 데이터를 넣지 않습니다. 구역별 API는 자료가 없으면 자료를 공개하지 않으며, 실제 학생·강사 반 소속 및 A/B 계정의 종단 간 구역 접근 실측은 **미실행**입니다. 로컬 가상 테스트 성공은 그 실측을 대신하지 않습니다.
- `npm test`, `npm run decider:test`, `npm run fixture:7`, `npm run build -- --local`, `npm run bundle`은 별개입니다. Bundle의 무로그인 확인은 실제 GET `/api/notes` 응답만 기록하며 구역 간 접근의 실제 실측이라고 주장하지 않습니다.

### 8단계 저장점 확인

가상 판정기 사례는 등록 메모 GET/PUT/DELETE 허용, 메모 목록 거부, 반 공지 단건 GET 허용·쓰기 거부, 강사 자료 거부, 미등록 기기 거부, 7단계 복합 이상·재확인 300초 이내 규칙 보존으로 구성됩니다. 직접 실행한 판정기 가상 회귀 28개는 통과했습니다. `npm run build -- --local`과 `npm run decider:test`, `npm test`, `npm run bundle`은 GitHub Actions의 단계별 결과로 확인해야 하며 실제 Supabase DB 권한 검증과 구분합니다. 기존 메모·로그인·소유자 검사는 보존하고 화면 메뉴는 변경하지 않았습니다. 현재 Production 배포는 최신 8단계 빌드 지원 커밋에서 READY로 확인되었습니다.

## 9단계 · 도플갱어를 찾고 권한을 거둡니다

`src/detect.mjs`는 `docs/DETECT_EVENTS.md`의 가상 사건 계약에 있는 `at`(시각), `method`(요청 종류), `identity.sub`(가명 사용자)만 읽습니다. 같은 가명 사용자의 `GET` 사건이 어느 연속된 10분 구간(경계 포함)에 **121건 이상**이면 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`만 반환합니다. 120건 이하, 서로 다른 사용자, 시간 창 밖의 사건, GET이 아닌 사건은 `{ action: 'observe' }`를 반환합니다. 입력 사건이 시간순이 아니어도 결과는 같습니다.

이 함수는 가상 사건에 대한 **회수 제안만** 반환하고 실제 기기·세션을 폐기하거나 운영 회수 API를 호출하지 않습니다. 현재 저장소에는 운영 반 엔진의 사건 전달·회수 집행 연결 실측이 없으며 `npm run detect:test` 통과를 실제 세션 차단이나 심판 평가로 주장하지 않습니다. 비밀키·토큰·메모 본문·실명·기기 ID·네트워크·지역을 탐지 조건이나 로그에 넣지 않습니다.

`aleph.config.json`의 `step`은 9입니다. 8단계의 메모 소유권 검사, 구역별 API·판정기, 7단계의 복합 이상·5분 추가 확인, 기존 공개 앱 URL과 로그인 설정을 변경하지 않습니다. `npm run detect:test`는 공식 가상 사건 6가지를 검사하며 `npm test`는 10분 경계, 순서 역전, 다른 사용자 분리, 비계약 필드 무시를 포함한 회귀 검사입니다. `npm run build -- --local`은 정적 빌드, `npm run bundle`은 커밋이 끝난 깨끗한 작업 트리에서 제출 JSON과 무로그인 API 자체 점검을 생성합니다.

**9단계 저장점:** 위 규칙과 기존 1~8단계의 자료실·판정기·구역별 API가 현재 구현 범위입니다. 제출 직전에는 GitHub Actions의 `ALEPH stage 9 verification` 성공 상태, Vercel Production READY 및 제출 Bundle의 9단계·커밋 일치를 확인합니다. 심판 제출은 사용자가 직접 진행합니다.

## 10단계 · 백업에서 자료실을 되살립니다

**안전한 사본 확인:** 9단계 심판 100점 통과 뒤, 10단계 침공 전에 확인한 Git 커밋 `cbdbbed3bb5f2c97bb5efeb82c0d9e7ef750c27c`의 구역별 안전 정책을 `backups/stage9-safe-policy.json`에 보관하고 SHA-256 `93e7db2e27ce5b19fc7f4125b2a0d65e0e4d3b080265814c156f229db253c6ab`로 고정했습니다. `npm run policy:preview`는 고정 해시를 검사한 다음 `fixtures/stage10-damaged-test-policy.json` 또는 `artifacts/stage10-test-policy.json`의 변경된 허용 경로·규칙 목록과 복구 대상 버전을 출력하며 실제 정책을 건드리지 않습니다. 사본이 없거나 해시가 다르면 실행을 중단합니다. 시험 정책만 반영할 때는 미리보기의 `safeHash`를 확인하고 `node scripts/policy-restore.mjs --apply --confirm-sha256=<확인한 safeHash>`를 실행합니다. 이 명령은 `artifacts/stage10-test-policy.json`에만 써서 다른 서비스 설정·감사 이력을 보존합니다. **운영 판정기 및 운영 보안 정책을 자동으로 되돌리는 기능은 포함하지 않았습니다.**

**B 단건 복원:** 10단계 침공을 준비하면서 운영 Supabase에 `stage10_private_verified_note_backup` 마이그레이션을 적용했습니다. 기존 6건의 가상 메모와 A 소유 4건·B 소유 1건·미소유 1건 분포를 검증한 다음 **B 한 건만** `public.stage10_note_backups`에 기록했습니다. 사본에는 원래의 `note_uuid`, `owner_id`, 제목, 본문 및 SHA-256이 들어 있으며 공개 저장소·제출 묶음·API 응답에는 본문과 소유자 식별자를 넣지 않습니다. RLS가 활성화돼 있고 `anon`·`authenticated` 역할의 직접 접근은 금지합니다. 사본 생성 시 ID·소유자·제목·내용 해시가 원본과 일치하는지 확인했습니다. 이 백업의 기준 커밋은 위 9단계 커밋이며, 백업을 다시 덮어쓰지 않습니다. SQL 스키마와 복구 함수를 `sql/production-10-verified-backup.sql`에 보관합니다.

**복구 서비스와 경로:** `POST /api/restore` (`api/restore.js`)가 복구 경로이며 `aleph.config.json`의 `restoreRoute`에도 `/api/restore`를 기록했습니다. 검증된 학생 B의 Bearer 로그인 또는 서명이 검증된 심판 B의 토큰에만 적용하며, 선택적 JSON `{"id":"메모UUID"}` 또는 `{"noteId":"메모UUID"}`를 받습니다. 요청 ID를 생략하더라도 서버는 B 사본이 정확히 한 건인 경우에만 복구합니다. **본문·소유자·권한을 요청값으로 받지 않습니다.** 서버 전용 `stage10_restore_verified_note`가 트랜잭션 안에서 사본의 ID·소유자·내용 SHA-256을 검증하고 그 한 건만 UPDATE 또는 INSERT합니다. 다른 메모·운영 정책·기존 감사 기록은 수정하지 않고 성공한 복원 기록은 `stage10_restore_audit`에 추가합니다. 실패 시 서버는 짧은 오류 코드만 반환합니다. 이 경로는 학생 판정기 허용 경로가 아닌 복구 관리 경로입니다.

**복원 시험:** 운영 DB에서 B 메모를 일시적으로 변조·삭제하는 시나리오를 트랜잭션 내부에서 각각 테스트하고, 백업 해시로 복원됐는지 확인한 뒤 **시험 전체를 롤백**했습니다. 실제 자료와 복원 감사 기록은 변하지 않았습니다. 이는 DB 내부 복구 함수의 시험이며, 심판이 공격한 뒤 실제 HTTP `POST /api/restore`를 호출한 종단 간 시험은 **미실행**입니다.

**1~9단계 재시험 순서:** (1) 백업 `baseline_commit`·해시와 정책 미리보기를 검증하고 복원 대상 한 건만 확인 (2) B의 변조·삭제 및 POST 복구 후 ID·소유자·SHA-256 비교 (3) 로그인 전 `GET /api/notes` 접근 401 확인 (4) A 정상 단건 GET/PUT/DELETE 및 B의 A 메모 요청 404 확인 (5) 로그인·기기 등록/미등록·추가 인증 300초/301초 분기 확인 (6) 메모 목록 차단·반 공지 쓰기 거부·강사 자료 차단 및 서버 소유자 검사 (7) 10분 안 120/121회 탐지 observe/propose_revocation 확인 (8) 기타 기존 API·XDR 회귀 실행 및 감사 이력 보존 비교. `npm ci`, `npm test`, `npm run decider:test`, `npm run detect:test`, `npm run policy:preview`, `npm run fixture:7`, `npm run build -- --local`, `npm run bundle`로 코드/가상 연습과 제출 자료를 검사합니다. **실제 A/B 브라우저 로그인 및 심판 침공 후 1~9단계 HTTP 재전송은 아직 미실행이며, 테스트 결과를 만들어 기록하지 않습니다.**

**10단계 저장점:** 검증된 9단계 정책 사본과 B의 비공개 단건 백업, 시험 정책 복원 미리보기 및 확인 후 복원, B 전용 POST 복구 API, 1~9단계 재시험 순서를 갖췄습니다. 공식 침공이 발생한 뒤 실제 HTTP 복구와 전체 재시험은 심판 제출 전에 실행했다고 주장하지 않습니다. 제출용 `bundle-notes.json`과 `artifacts/submission.json`은 생성 산출물로 Git 커밋 대상이 아닙니다.

## 11단계 · 나만의 접속 앱을 완성합니다

**설치형 웹앱:** 기존 자료실 `/`에 `public/manifest.webmanifest`, 192×192·512×512 PNG 및 SVG 아이콘을 연결했습니다. 앱 이름은 **BYTE BACK 안전 자료실**입니다. 별도 실행 파일은 설치하지 않습니다. `public/sw.js`는 정적 `/offline.html` 안내 한 페이지만 캐시하고, 보호 API·메모·기기키·세션을 캐시하지 않습니다. 오프라인에서는 자료를 표시하지 않습니다. 브라우저가 앱을 설치했다고 해서 기기 승인이나 로그인 검증을 건너뛰지 않습니다.

**승인 요청과 상태:** 로그인 후 `public/index.html`에 기기 승인 요청·상태 확인 버튼이 표시됩니다. `POST /api/device`는 확인된 로그인 사용자의 요청으로 서버 DB `stage11_devices`에 소유자와 P-256 공개키만 기록하며 항상 `pending`으로 시작합니다. **버튼으로 자신을 승인하는 기능은 없습니다.** 서버 관리자가 기기·사용자 요청을 별도로 확인한 뒤 운영 Supabase의 상태를 `approved`로 지정해야 합니다. 이후 `GET /api/device?id=...`가 서버 상태와 해당 개인키 서명을 검사해서 승인 결과를 반환합니다. 승인 전에는 브라우저가 자료를 표시하지 않고, 보호 메모 API도 미승인 요청을 403으로 거부합니다.

**서명과 서버 측 권한:** `src/device-proof.mjs`는 `GET/POST/PUT/DELETE /api/notes` 및 단건 메모, 반 공지와 강사 관리 자료 요청에서 검증된 사용자 ID·승인 기기의 공개키·ECDSA P-256 서명·시각·일회용 nonce를 확인합니다. 서명은 HTTP 메서드, 정확한 URL 경로와 쿼리, 요청 본문 SHA-256, 시각, nonce에 결합되므로 경로·수정 본문을 바꾸면 거부됩니다. 재전송 nonce는 DB의 유일키로 차단합니다. 기기 승인과 별도로 기존 소유자·반 소속·관리자 역할 검증도 유지합니다. 복구 관리자 전용 `POST /api/restore`는 이전 10단계 서명된 심판 복구 토큰 계약을 보존합니다.

**비밀값 보존:** `public/device-client.js`는 개인키를 추출 불가 `CryptoKey`로 **현재 화면의 JS 메모리에서만** 사용합니다. `localStorage`, `sessionStorage`, `IndexedDB`에 기기 개인키를 쓰지 않으며 Supabase Auth `persistSession: false`로 토큰 영속 저장도 비활성화했습니다. **새로고침·앱 재실행으로 이 임시 개인키는 사라지므로 재로그인 및 새 기기 승인 요청이 필요합니다.** 설치 표시나 기존 승인만으로 재시작 후 자동 접근할 수는 없습니다. 지속형 하드웨어 키/WebAuthn 등록·기기 승인 엔진과의 연동은 이번에 구현·실측하지 않았습니다.

**운영 DB/승인:** `sql/production-11-device-approval.sql`을 Supabase 운영 프로젝트에 `stage11_device_approval_proof` 마이그레이션으로 적용했습니다. `stage11_devices`와 `stage11_device_nonces`는 RLS 활성화 및 일반 사용자 DB 직접 권한 회수 상태입니다. 승인 권한은 서버 관리자만 가집니다. 실제 사용자·기기 승인 정보를 임의로 생성하지 않았습니다. 승인된 기기와 서버의 **실제 브라우저 E2E 시험은 관리자 승인 후 수행해야 하며 미실행**입니다.

**검증 순서:** 먼저 무로그인 보호 API → 401, 로그인한 미승인 기기 → 403, 승인 요청 → pending, 관리자가 검증해 approved 지정, 서명된 승인 기기의 정상 메모 조회·추가·변경·삭제 확인, 동일 서명으로 경로·본문 변경 → 403, 재전송 → 403, 앱 오프라인 안내 확인. 기존 1~10단계는 `npm ci`, `npm test`, `npm run decider:test`, `npm run detect:test`, `npm run policy:preview`, `npm run fixture:7`, `npm run build -- --local`, `npm run bundle`로 회귀 검사합니다. 이 로컬 검사를 실제 계정 승인이나 심판 통과로 표시하지 않습니다.

**11단계 저장점:** 기존 1~10단계 기능과 안전 정책을 보존하고 설치형 PWA 설정, 오프라인 안내, 서버 기반 기기 승인 요청·상태 조회, 보호 API의 기기별 요청 서명 검사 및 재전송 거부를 추가했습니다. 앱 설치나 승인 요청 버튼만으로 권한을 부여하지 않습니다. 기기 개인키와 토큰은 브라우저 영구 저장소에 쓰지 않습니다. 실제 관리자 승인과 승인 후 브라우저 종단 간 정상 접근은 아직 실측하지 않았습니다. 제출 묶음은 커밋 후 GitHub Actions의 `ALEPH stage 11 verification`에서 생성합니다.

## 12단계 · 탈환 작전실

**기준 저장점:** 11단계 저장점 `2c798e41aef46c8b22a2357ddf45cfa4fd4c51e1`과 기존 판정기·탐지기·복구·접속 앱을 보존하고 12단계 보안 관찰 기능만 추가했습니다. 설치·실행·중지·복구의 정확한 절차와 아래 근거를 구분합니다.

**학생 구현:** `public/index.html`의 **탈환 작전실 열기**를 누르면 `public/operations-dashboard.js`가 `GET /api/operations`의 실제 서버 응답을 읽어 요약 카드와 요청 결과표를 표시합니다. `api/operations.js`는 로그인 사용자에 대해 승인된 기기의 서명과 nonce를 확인한 후, `stage11_devices`의 승인·대기·회수 상태, `stage10_restore_audit`의 복구 횟수, `stage10_note_backups`의 사본 버전만 읽습니다. **메모 본문·가명 사용자·토큰·기기 개인키는 반환·표시하지 않습니다.** 판정기 규칙의 개수는 `src/decider.mjs`의 실제 `RULE_IDS`에서, 폭주 탐지 기준은 `src/detect.mjs`의 구현 계약에서 따옵니다. 이 정적 구현 정보는 운영 판정·탐지 실행 건수가 아닙니다. 운영 엔진의 개별 판정 기록·탐지 이벤트·회수 실적은 연결되지 않았으므로 **미연결·미확인**을 보여 줍니다. 백업이 로그인 사용자의 자료와 무관하면 버전은 미확인으로 표시합니다. 네트워크/DB 오류는 0건 성공으로 환산하지 않습니다.

**1~11단계 재시험 표:** `src/operations-report.mjs`은 공식 41종 공격의 원본 ID·입력·판정을 받지 못했으므로 `challenge-01`~`challenge-41`이라는 **로컬 자리표시자**를 만들고 각각 `미실행`, 실제 HTTP 결과·요청 ID·검사 시각은 없음으로 표시합니다. `GET /api/operations`은 무인증 `GET /api/notes`를 별도로 실제 호출해 HTTP 상태, 비민감한 오류 코드, 임의 요청 ID, 확인 시각을 `live_http_response` 근거로 표시하되, **이 1건을 공식 41종 완료로 세지 않습니다.** 기대 결과와 실제 결과는 별도 열이며, 실제로 요청하지 않은 A 정상 로그인·B 타인 메모 조회·미등록 기기·회수 신원 재사용·복구 후 서명 없는 변경·구역 밖 조회 등은 미실행 상태를 유지합니다. 심판의 41종 통과는 별도의 심판 기록으로만 판단합니다.

**실제 확인 순서 (미실행을 통과로 만들지 않음):** (1) 무인증 메모 목록 GET 401, (2) A 정상 로그인·승인 기기 정상 읽기 200, (3) B가 A 단건 메모 접근 시 404, (4) 미등록·회수된 기기의 접근 403, (5) 7단계 복합 이상 요청의 `step_up`과 검증된 재인증, (6) 8단계 메모 목록·반 공지 쓰기·강사 자료 제한, (7) 9단계 120건 observe/121건 propose_revocation, (8) 10단계 백업 검증·복구 후 소유자·SHA256, (9) 11단계 서명 누락·요청 경로 변조·본문 변조·nonce 재전송 거부, (10) 12단계 화면의 서버 데이터 일치. 안전한 가상 실습과 실제 HTTP 실측, 공식 심판 41종은 별도 결과로 표시해야 합니다. 현재 서버 실측은 대시보드를 승인 기기에서 열 때 실행하는 무인증 API 검사 1개에 한정됩니다.

**설치/실행:** Node.js 22 이상에서 `git clone https://github.com/happyhamster61/choi-bujang-secret-vault-3.git`, `cd choi-bujang-secret-vault-3`, `npm ci`, `npm test`, `npm run decider:test`, `npm run detect:test`, `npm run policy:preview`, `npm run build -- --local` 순으로 실행합니다. 학생 구현은 `src/decider.mjs` 판정 규칙, `src/detect.mjs` 탐지, `api/restore.js` B 한 건 복원, `public/` 설치형 앱, `api/operations.js` 대시보드입니다. **판정 사건의 확인·전달, 신원·기기 검증, 회수 제안의 집행은 제공된 ALEPH SDP 엔진의 책임**이며, 엔진 자체를 학생이 새로 구현하거나 운영 이벤트 수집기가 연결된 것처럼 표시하지 않습니다. 설정된 발급자 주소와 공개 원본 API, 허용 경로는 `aleph.config.json`을 참조하고, 서버 비밀값은 Vercel의 비공개 환경변수에만 유지합니다.

**배포/중지/복구:** 기존 Vercel 저장소 연결로 자동 배포하며 `npm run build`로 정적 공개 파일을 생성합니다. 중지는 Vercel 프로젝트에서 배포를 일시 중지하거나 접근을 차단하는 관리 절차로 수행하고, 개인키·비밀값을 소스에 넣지 않습니다. 데이터 복구는 10단계의 검증된 비공개 백업을 사용하고 인증된 B 자원만 `POST /api/restore`로 복구합니다. 시험 정책 비교는 `npm run policy:preview`로, 확인된 SHA256을 사용한 **시험 정책에 한해서만** 복원을 진행합니다. 감사 이력과 다른 메모는 보존합니다. `npm run bundle`은 깨끗한 커밋 뒤 GitHub Actions에서 실행하여 제출 JSON과 자체 점검을 만들며, 이를 41종 실측 근거로 주장하지 않습니다. 보호 자료 API는 이전 단계의 인증·소유자·서명 검사를 그대로 사용합니다.

**12단계 저장점:** 실제 HTTP 1건과 DB 응답에서 확인된 상태만 작전실 대시보드에 표시하고, 공식 41종은 요청별 미실행으로 구분했습니다. 정책 규칙·탐지·회수·백업 버전의 출처와 미연결 상태를 명시했으며 1~11단계 설치·실행·중지·복구·재시험 절차를 README에 기록했습니다. 모든 학생 기능은 기존 ALEPH SDP 제공 엔진과 구분하며 실제 41종 통과 여부는 공식 심판 결과로만 판단합니다. 이번 변경은 운영 메모 본문과 감사 이력을 수정하지 않습니다.

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

## 12단계 제출 자기 점검 정정

`697a176` 이후 `src/attack-check.mjs`의 제출 점검은 기록된 심판 요청 근거가 없으면 `notes_list_without_login`을 `not_run`으로 유지하며 대체 HTTP 요청을 보내지 않습니다. 대시보드의 별도 실시간 HTTP 점검과 제출 묶음의 기록은 구별합니다. 회귀 검사는 3~12단계 전체에서 이 동작과 배포 주소 검증을 확인합니다. 이전 절의 Bundle이 HTTP 요청을 보낸다는 설명은 현재 동작에 적용되지 않습니다.
