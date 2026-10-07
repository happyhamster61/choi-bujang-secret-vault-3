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

로그인 사용자는 자료실 화면에서 메모를 추가·수정·삭제할 수 있습니다. 목록은 검증된 로그인 사용자의 `owner_id`로 조회하며, 새 메모의 소유자 ID는 서버가 토큰에서 확인해 저장합니다. 단건 `GET`, `PUT`, `DELETE`에는 아직 소유자 검사가 없습니다. 이 의도된 허점은 4단계에서 고칩니다.

Supabase SQL Editor에서 `sql/production-3-notes-uuid.sql`을 실행해 기존 bigint 기본 키를 유지하면서 API 메모 UUID 열을 추가합니다. 이 마이그레이션은 기존 네 건의 가상 메모를 변경하거나 삭제하지 않습니다. 기존 행은 `owner_id`가 비어 있으므로 사용자별 목록에는 나타나지 않습니다.

로컬 정적 빌드는 `npm run build -- --local`로 확인합니다. 제출 자료 생성은 Git 작업 트리가 깨끗하고 저장 설정이 커밋된 상태에서 `npm run bundle`을 실행합니다. bundle은 실제 배포에 보낸 무로그인 요청의 관찰 결과만 자체 점검으로 기록하며, 실제 심판 판정으로 간주하지 않습니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 정적 화면을 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 Supabase 연결을 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/api/notes`의 응답을 확인합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
