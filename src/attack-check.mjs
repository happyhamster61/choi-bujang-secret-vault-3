// Student self-check: make only a read-only request without a login token.
// Record the observed HTTP result; do not report it as a judge decision.
export async function runAttackChecks(config) {
  if (![3, 4].includes(config.step)) {
    throw new Error('3·4단계 제출 점검은 aleph.config.json의 step 3 또는 4가 필요합니다.');
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

  const response = await fetch(new URL('/api/notes', app), {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });
  let errorCode = '';
  try {
    const result = await response.json();
    if (typeof result?.error === 'string') errorCode = result.error;
  } catch {
    // Record the HTTP result without copying response bodies into the bundle.
  }

  return [{
    attackId: 'notes_list_without_login',
    expected: 'HTTP 401 LOGIN_REQUIRED',
    observed: `HTTP ${response.status}${errorCode ? ` ${errorCode}` : ''}`,
  }];
}
