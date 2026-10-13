const PATTERNS = Object.freeze([
  Object.freeze({
    name: '관리자 그룹 추가',
    conditions: "rule.mitre에 T1078이 있고 data.group이 'administrators'이며 rule.description에 관리자 그룹 추가·재추가 표현이 포함됨",
    evidence: 'T1078 태그, administrators 그룹 값, 그룹 변경 설명이 함께 있는 경보를 찾습니다. 그룹 변경만으로 계정 탈취를 확정하지 않습니다.',
    matches(alert, description) {
      const groupChange = [
        '관리자 그룹에 추가됐습니다',
        '관리자 그룹에 들어가고',
        '관리자 그룹 추가와',
        '다시 관리자로 들어왔습니다',
      ].some((phrase) => description.includes(phrase));
      return hasTechnique(alert, 'T1078')
        && typeof alert?.data?.group === 'string'
        && alert.data.group.toLowerCase() === 'administrators'
        && groupChange;
    },
    confidence: 0.68,
  }),
  Object.freeze({
    name: '처음 보는 주소의 관리자 명령',
    conditions: "rule.mitre에 T1068이 있고 rule.description에 '처음 보는 주소'와 '관리자 명령'이 모두 포함됨",
    evidence: 'T1068 태그와 처음 보는 주소의 관리자 명령이라는 설명을 함께 확인합니다. 주소 이력과 명령 식별자는 구조화 필드에 없습니다.',
    matches(alert, description) {
      return hasTechnique(alert, 'T1068')
        && description.includes('처음 보는 주소')
        && description.includes('관리자 명령');
    },
    confidence: 0.78,
  }),
  Object.freeze({
    name: '시간 외로 기록된 권한 사용',
    conditions: "rule.mitre에 T1068 또는 T1078이 있고 rule.description에 '수업 시간 밖' 또는 '업무처럼 보이지 않는 시각'과 관리자 명령·그룹 추가 등 권한 사용 표현이 함께 포함됨",
    evidence: 'pv-03과 pv-07 설명의 시간 외 표현을 단서로 삼습니다. 공식 업무 일정 필드는 없어 설명 문구만으로 시간 외 여부를 확인합니다.',
    matches(alert, description) {
      const outsideHours = description.includes('수업 시간 밖')
        || description.includes('업무처럼 보이지 않는 시각');
      const privilegedUse = description.includes('관리자 명령')
        || description.includes('관리자 그룹 추가');
      return (hasTechnique(alert, 'T1068') || hasTechnique(alert, 'T1078'))
        && outsideHours
        && privilegedUse;
    },
    confidence: 0.55,
  }),
]);

function hasTechnique(alert, technique) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(technique);
}

function actionFor(confidence) {
  return confidence >= 0.85
    ? 'block'
    : confidence >= 0.5
      ? 'alert'
      : 'record';
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const matchedPatterns = PATTERNS.filter((pattern) => pattern.matches(alert, description));

  if (matchedPatterns.length === 0) {
    const confidence = 0.1;
    return {
      action: actionFor(confidence),
      confidence,
      reason: '일치 패턴 없음: 현재 경보 필드에서 권한 악용 근거가 부족함',
    };
  }

  const names = matchedPatterns.map((pattern) => pattern.name);
  const allSignalsMatch = matchedPatterns.length === PATTERNS.length;
  const strongCorroboration = names.includes('관리자 그룹 추가')
    && names.includes('시간 외로 기록된 권한 사용')
    && hasTechnique(alert, 'T1068')
    && hasTechnique(alert, 'T1078');
  const confidence = allSignalsMatch || strongCorroboration
    ? 0.9
    : matchedPatterns.length > 1
      ? 0.8
      : Math.max(...matchedPatterns.map((pattern) => pattern.confidence));
  const action = actionFor(confidence);
  const uncertainty = action === 'block'
    ? '여러 신호가 함께 일치하는 차단 판단이며 계정 탈취 또는 권한 상승 성공 자체를 확정하지 않음'
    : '로그 신호 일치이며 계정 탈취 또는 권한 상승 성공 자체를 확정하지 않음';

  return {
    action,
    confidence,
    reason: `${names.join(', ')}: ${uncertainty}`,
  };
}
