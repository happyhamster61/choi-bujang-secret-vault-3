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
  return {
    id: typeof row.id === 'string' ? row.id : 'unknown',
    name: typeof row.name === 'string' ? row.name : '시험',
    expected: typeof row.expected === 'string' ? row.expected : '미확인',
    observed: typeof row.observed === 'string' ? row.observed : null,
    requestId: typeof row.requestId === 'string' ? row.requestId : null,
    checkedAt: typeof row.checkedAt === 'string' ? row.checkedAt : null,
    status: row.status,
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
