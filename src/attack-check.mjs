// No judge request evidence exists for notes_list_without_login.
// Do not claim an observed HTTP result or send a substitute request.
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

  return [{
    attackId: 'notes_list_without_login',
    expected: 'HTTP 401 LOGIN_REQUIRED',
    observed: 'not_run',
  }];
}
