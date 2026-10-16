import { createRequire } from 'node:module';
const stageReport = createRequire(import.meta.url)('../docs/stage-verification.json');
// Stage 12: combine only observed server results; unavailable is not success.
export const TOTAL_CHALLENGE_CASES = 41;
export const STAGE_LABELS = Object.freeze([
  '공개자료/무인증', '로그인과 신원', '메모 소유권', '타인 메모 거부',
  '자료 API', '등록 기기 판정', '복합 이상 탐지', '자원별 접근',
  '폭주 탐지·회수 제안', '백업 복구', '서명된 접속 앱'
]);
export function unexecutedChallengeCases() {
  // Official 41 challenge IDs are not supplied by this repository.
  return Array.from({ length: TOTAL_CHALLENGE_CASES }, (_, index) => ({
    id: 'challenge-' + String(index + 1).padStart(2, '0'),
    name: '공식 공격 사례 ' + (index + 1),
    expected: '공식 심판 계약에서 확인 필요',
    observed: null, requestId: null, checkedAt: null,
    status: 'not_run', source: 'unavailable_official_case_definition'
  }));
}
export function sanitizeCheck(row) {
  const allowed = ['observed', 'not_run', 'unavailable'];
  if (!row || !allowed.includes(row.status)) throw new Error('invalid_check');
  if (row.status === 'observed' && (typeof row.observed !== 'string'
      || !row.observed.trim() || !Number.isFinite(Date.parse(row.checkedAt)))) {
    throw new Error('missing_observation');
  }
  if (row.status === 'not_run' && (row.observed != null || row.requestId != null
      || row.checkedAt != null)) throw new Error('unexecuted_has_evidence');
  return {
    id: typeof row.id === 'string' ? row.id : 'unknown',
    name: typeof row.name === 'string' ? row.name : '시험',
    expected: typeof row.expected === 'string' ? row.expected : '미확인',
    observed: typeof row.observed === 'string' ? row.observed : null,
    requestId: typeof row.requestId === 'string' ? row.requestId : null,
    checkedAt: typeof row.checkedAt === 'string' ? row.checkedAt : null,
    status: row.status,
    testedCommit: /^[a-f0-9]{40}$/i.test(row.testedCommit ?? '') ? row.testedCommit : null,
    stage: Number.isInteger(row.stage) ? row.stage : null,
    source: typeof row.source === 'string' ? row.source : 'not_run'
  };
}
export function summarizeChecks(checks) {
  if (!Array.isArray(checks)) throw new TypeError('invalid_checks');
  return {
    observed: checks.filter(x => x.status === 'observed').length,
    unexecuted: checks.filter(x => x.status === 'not_run').length,
    unavailable: checks.filter(x => x.status === 'unavailable').length,
  };
}

export function stageVerificationChecks() {
  return stageReport.stages.flatMap(stage => ['local','live'].map(mode => {
    const record = stage[mode];
    return sanitizeCheck({
      id: `stage-${stage.stage}-${mode}`, stage: stage.stage,
      name: `${stage.stage}단계 ${stage.name} · ${mode === 'local' ? '로컬 검사' : '운영 API 검사'}`,
      ...record, testedCommit: record.commit,
    });
  }));
}
export function buildEvidenceGroups({probe,submissionAttempts,deploymentCommit}) {
  const submission = submissionAttempts.map(item => sanitizeCheck({
    id:item.attackId, name:'제출 자기 점검 · '+item.attackId,
    expected:item.expected, observed:null, requestId:null, checkedAt:null,
    status:'not_run', source:'submission_not_run',
    testedCommit:deploymentCommit,
  }));
  // No recorded judge request is present. Never transplant an unrelated probe.
  if (submissionAttempts.some(item => item.observed !== 'not_run')) {
    throw new Error('submission_evidence_requires_separate_review');
  }
  const group = (label,checks,note) => ({label,checks,summary:summarizeChecks(checks),note});
  return {
    submission:group('제출 Bundle 자기 점검',submission,
      'src/attack-check.mjs의 미실행 기록입니다. 작전실 HTTP 응답이나 심판 요청 기록이 아닙니다.'),
    dashboardApi:group('작전실 별도 API 관측',[probe],
      '작전실이 별도로 보낸 학생 자기 점검 요청입니다. 요청 ID는 이 관측용이며 공식 심판 요청 ID가 아닙니다.'),
    stageVerification:group('1~11단계 검사 기록',stageVerificationChecks(),
      '기록에 적힌 testedCommit의 로컬 검사와 독립 HTTP 관찰입니다. 현재 배포 전체 통과를 뜻하지 않습니다.'),
    officialChallenges:group('공식 41종 공격',unexecutedChallengeCases(),
      '공식 원본 사례와 요청별 결과가 제공되지 않아 모두 미실행입니다. 12단계 통과와 구별합니다.'),
  };
}
