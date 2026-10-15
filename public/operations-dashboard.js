// Stage 12: never infer success from the UI; render only sanitized evidence from API.
export function mountOperationsDashboard({ getSession, deviceGate }) {
  const panel = document.querySelector('#operations-panel');
  const status = document.querySelector('#operations-status');
  const openButton = document.querySelector('#operations-open');
  const refreshButton = document.querySelector('#operations-refresh');
  const metrics = document.querySelector('#operations-metrics');
  const checksBody = document.querySelector('#operations-checks');
  const stamp = document.querySelector('#operations-timestamp');
  const headline = document.querySelector('#operations-checks-summary');
  const tab = document.querySelector('#operations-tab');
  let loaded = false;

  function card(title, main, detail) {
    const el = document.createElement('article');
    el.className = 'ops-metric';
    const h = document.createElement('h3');
    h.textContent = title;
    const number = document.createElement('strong');
    number.textContent = main;
    const sub = document.createElement('p');
    sub.textContent = detail;
    el.append(h, number, sub);
    return el;
  }
  function observedCount(value) {
    return value?.status === 'observed' && Number.isInteger(value.count)
      ? String(value.count) : '미확인';
  }
  function label(row) {
    if (row?.status === 'observed') return '실측';
    if (row?.status === 'unavailable') return '조회 실패';
    return '미실행';
  }
  function render(report) {
    if (!report || report.schema !== 'byteback.operations.v1'
      || !report.evidence || !Array.isArray(report.evidence.checks)) {
      throw new Error('작전실 보고서 형식이 올바르지 않습니다.');
    }
    const checks = report.evidence.checks;
    metrics.replaceChildren(
      card('판정기', String(report.policy?.ruleCount ?? '미확인'),
        '저장소에 구현된 규칙 수 · 운영 실측 아님'),
      card('폭주 탐지', report.detection?.configured ? '설정됨' : '미확인',
        '10분 안에 GET 121회 이상 · 운영 사건: 연결되지 않음'),
      card('기기 승인', observedCount(report.devices?.approved),
        '로그인 사용자 소유 · DB 실측 승인 기기 수'),
      card('기기 회수', observedCount(report.devices?.revoked),
        '로그인 사용자 소유 · DB 상태 / 운영 회수 실행: 미확인'),
      card('백업 복구', observedCount(report.recovery?.ownRestoreAudit),
        '로그인 사용자의 DB 복구 감사 기록 수'),
      card('사전 백업 버전', report.recovery?.backup?.commit
        ? report.recovery.backup.commit.slice(0, 12) : '미확인',
        '서버 백업 기록에서 조회 · 본문 표시 안 함')
    );
    checksBody.replaceChildren(...checks.map(check => {
      const tr = document.createElement('tr');
      const fields = [check.id, check.name, check.expected,
        check.observed ?? '—', check.requestId ?? '—',
        check.checkedAt ?? '—', label(check)];
      for (const value of fields) {
        const td = document.createElement('td');
        td.textContent = String(value);
        tr.append(td);
      }
      return tr;
    }));
    const summary = report.evidence.summary;
    headline.textContent = '실측 ' + summary.observed + '건 · 미실행 ' +
      summary.unexecuted + '건 · 조회 실패 ' + summary.unavailable +
      '건 (공식 41종은 독립적으로 미실행)';
    stamp.textContent = '서버 확인 시각: ' + (report.checkedAt ?? '미확인');
    status.textContent = '서버 응답을 확인했습니다. 이 화면 자체는 심판 통과 증거가 아닙니다.';
    loaded = true;
  }
  async function reload() {
    const session = getSession();
    if (!session?.access_token || !deviceGate.isApproved()) {
      metrics.replaceChildren();
      checksBody.replaceChildren();
      headline.textContent = '승인된 기기에서만 보고서를 조회할 수 있습니다.';
      status.textContent = '미확인: 로그인과 서버 기기 승인이 필요합니다.';
      loaded = false;
      return;
    }
    refreshButton.disabled = true;
    status.textContent = '서버의 실제 결과를 읽는 중입니다.';
    try {
      const response = await deviceGate.signedFetch('/api/operations',
        { cache: 'no-store' });
      if (!response.ok) throw new Error('작전실 API HTTP ' + response.status);
      render(await response.json());
    } catch (error) {
      metrics.replaceChildren();
      checksBody.replaceChildren();
      headline.textContent = '읽지 못한 시험은 통과로 표시하지 않습니다.';
      status.textContent = '조회 실패: ' + error.message;
      loaded = false;
    } finally {
      refreshButton.disabled = false;
    }
  }
  openButton.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    openButton.setAttribute('aria-expanded', String(!panel.hidden));
    if (!panel.hidden && !loaded) void reload();
  });
  refreshButton.addEventListener('click', reload);
  function onSessionChanged() {
    tab.hidden = !getSession()?.access_token;
    loaded = false;
    metrics.replaceChildren();
    checksBody.replaceChildren();
    status.textContent = '서버 확인 대기 중';
    headline.textContent = '조회 전 결과는 미확인입니다.';
  }
  onSessionChanged();
  return { reload, onSessionChanged };
}
