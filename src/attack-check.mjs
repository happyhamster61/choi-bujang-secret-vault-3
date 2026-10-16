// Submission self-check plan for stages 1–11, in stage order.
// No HTTP requests are sent here. Historical/local/dashboard results are not
// evidence for these attempts; do not turn them into observed HTTP statuses.
// This list is not the official 41-case judge suite.
export const STAGE_ATTACK_CHECKS = Object.freeze([
  {
    "attackId": "stage_01_deployment_identity",
    "expected": "1단계: GET /aleph.json HTTP 200; 배포 SHA 일치",
    "observed": "not_run"
  },
  {
    "attackId": "notes_list_without_login",
    "expected": "2단계: GET /api/notes HTTP 401 LOGIN_REQUIRED; 공개 /data.json HTTP 404",
    "observed": "not_run"
  },
  {
    "attackId": "stage_03_owner_notes_crud",
    "expected": "3단계: 정상 로그인·승인 기기의 본인 메모 CRUD 허용",
    "observed": "not_run"
  },
  {
    "attackId": "stage_04_other_owner_notes",
    "expected": "4단계: 타인 메모 GET·PUT·DELETE HTTP 404",
    "observed": "not_run"
  },
  {
    "attackId": "stage_05_server_api_only",
    "expected": "5단계: 정상 서버 경유 자료 요청 허용; 원본 API 우회 거부",
    "observed": "not_run"
  },
  {
    "attackId": "stage_06_registered_device",
    "expected": "6단계: 등록 기기 허용; 미등록·회수 기기 거부",
    "observed": "not_run"
  },
  {
    "attackId": "stage_07_step_up",
    "expected": "7단계: 복합 이상 요청 step_up; 검증된 재인증 후 정상 접근",
    "observed": "not_run"
  },
  {
    "attackId": "stage_08_resource_zones",
    "expected": "8단계: 반 소속·강사 권한에 맞는 자원 허용; 구역 밖 요청 거부",
    "observed": "not_run"
  },
  {
    "attackId": "stage_09_burst_revocation",
    "expected": "9단계: 10분 120회 observe; 121회 propose_revocation; 운영 회수 집행 확인",
    "observed": "not_run"
  },
  {
    "attackId": "stage_10_verified_restore",
    "expected": "10단계: 인증된 복구 후 ID·소유자·해시 일치; 무인증 복구 거부",
    "observed": "not_run"
  },
  {
    "attackId": "stage_11_signed_device",
    "expected": "11단계: 승인 기기 서명 요청 허용; 변조·서명 누락·nonce 재전송 거부",
    "observed": "not_run"
  }
].map(row => Object.freeze(row)));
export async function runAttackChecks(config) {
  if (![3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) {
    throw new Error('3~12단계 제출 점검은 aleph.config.json의 step 3~12가 필요합니다.');
  }

  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 확인해 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || !app.hostname.endsWith('.vercel.app')) {
    throw new Error('aleph.config.json의 실제 Vercel 배포 주소를 확인해 주세요.');
  }

  return STAGE_ATTACK_CHECKS.map(row => ({ ...row }));
}
