const PATTERNS = Object.freeze([
  Object.freeze({
    name: '짧은 시간 같은 주소의 로그인 실패 연속',
    condition: '짧은 시간 동안 같은 출발 주소에서 로그인 실패가 반복됩니다.',
    evidence: 'MITRE ATT&CK T1110은 반복적으로 비밀번호를 추측해 계정 접근을 시도하는 행위를 무차별 대입으로 설명합니다.',
  }),
  Object.freeze({
    name: '여러 계정에 같은 비밀번호 대입',
    condition: '같은 출발 주소가 짧은 시간에 여러 계정으로 동일한 비밀번호를 시도합니다.',
    evidence: 'MITRE ATT&CK T1110.003 Password Spraying은 여러 계정에 비밀번호를 시도하는 무차별 대입 하위 기법입니다.',
  }),
]);

const ACTIONS = Object.freeze({ block: 0.85, alert: 0.5 });

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const accounts = typeof alert?.data?.accounts === 'string'
    ? alert.data.accounts.split(',').filter(Boolean).length
    : 0;
  const failedLogin = /로그인 실패|실패가|실패\s*\d+건/.test(description);
  const multiAccountSpray = /같은 비밀번호/.test(description)
    && (/여러 계정|서로 다른 계정|계정\s*\d+개/.test(description) || accounts > 1);
  const shortBurst = /\d+분 안|\d+분 동안|\d+분 이내|\d+초 안|짧은 시간/.test(description);
  const firstPattern = PATTERNS[0].name;
  const secondPattern = PATTERNS[1].name;

  if (multiAccountSpray && level >= 10) {
    return { action: 'block', confidence: 0.95, reason: secondPattern };
  }

  if (failedLogin && level >= 10 && (count >= 15 || (shortBurst && count >= 10))) {
    return { action: 'block', confidence: 0.9, reason: firstPattern };
  }

  if (failedLogin && level >= 5 && level <= 9) {
    return { action: 'alert', confidence: 0.65, reason: firstPattern };
  }

  if (multiAccountSpray || (failedLogin && count >= 3)) {
    return { action: 'alert', confidence: 0.6, reason: multiAccountSpray ? secondPattern : firstPattern };
  }

  return { action: 'record', confidence: 0.1, reason: '일치 패턴 없음' };
}
