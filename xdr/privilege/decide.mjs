const PATTERNS = Object.freeze([
  Object.freeze({
    name: '관리자 그룹 추가',
    confidence: 0.68,
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
  }),
  Object.freeze({
    name: '처음 보는 주소의 관리자 명령',
    confidence: 0.78,
    matches(alert, description) {
      const unfamiliarAddress = description.includes('처음 보는 주소')
        || description.includes('요청 주소는 처음 봅니다');
      const privilegedCommand = description.includes('관리자 명령')
        || description.includes('권한 명령');
      return hasTechnique(alert, 'T1068') && unfamiliarAddress && privilegedCommand;
    },
  }),
  Object.freeze({
    name: '시간 외로 기록된 권한 사용',
    confidence: 0.55,
    matches(alert, description) {
      const outsideHours = description.includes('수업 시간 밖')
        || description.includes('업무처럼 보이지 않는 시각');
      const privilegedUse = description.includes('관리자 명령')
        || description.includes('권한 명령')
        || description.includes('관리자 그룹 추가');
      return (hasTechnique(alert, 'T1068') || hasTechnique(alert, 'T1078'))
        && outsideHours
        && privilegedUse;
    },
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

function isExplicitlyNonPrivileged(alert, description) {
  const group = typeof alert?.data?.group === 'string'
    ? alert.data.group.toLowerCase()
    : '';
  return (group !== '' && group !== 'administrators'
      && (description.includes('관리자 그룹은 아닙니다')
        || description.includes('과제 그룹')
        || description.includes('새 로컬 그룹')))
    || description.includes('변경은 없습니다')
    || description.includes('그룹 목록을 읽은 뒤');
}

function isPromotionThenCommand(alert, description) {
  return hasTechnique(alert, 'T1068')
    && hasTechnique(alert, 'T1078')
    && description.includes('방금 관리자가 된')
    && description.includes('관리자 명령');
}

function isGroupThenCommand(description, groupSignal) {
  return groupSignal
    && description.includes('곧바로')
    && (description.includes('권한 명령') || description.includes('관리자 명령'));
}

function isMultiAccountGroupAddition(alert, description, groupSignal) {
  const count = Number(alert?.data?.count);
  return groupSignal
    && Number.isSafeInteger(count)
    && count >= 3
    && description.includes('같은 주소')
    && description.includes('계정')
    && description.includes('관리자 그룹');
}

function hasAmbiguousPrivilegeActivity(alert, description) {
  if (!hasTechnique(alert, 'T1068')) return false;
  return [
    '관리자 명령',
    '권한 명령',
    '관리자 권한으로 바뀌었',
    '권한 상승',
    '다른 계정의 권한',
  ].some((phrase) => description.includes(phrase));
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';

  if (isExplicitlyNonPrivileged(alert, description)) {
    const confidence = 0.1;
    return {
      action: actionFor(confidence),
      confidence,
      reason: '비관리자 그룹 또는 변경 없는 조회만 확인되어 record',
    };
  }

  const matchedPatterns = PATTERNS.filter((pattern) => pattern.matches(alert, description));
  const names = matchedPatterns.map((pattern) => pattern.name);
  const groupSignal = names.includes('관리자 그룹 추가');
  const unfamiliarCommandSignal = names.includes('처음 보는 주소의 관리자 명령');
  const offHoursSignal = names.includes('시간 외로 기록된 권한 사용');

  const strongSignals = [];
  if (isPromotionThenCommand(alert, description)) {
    strongSignals.push('T1068·T1078 및 관리자 승격 직후 명령');
  }
  if (unfamiliarCommandSignal && offHoursSignal) {
    strongSignals.push('처음 보는 주소의 관리자 명령과 시간 외 사용');
  }
  if (isGroupThenCommand(description, groupSignal)) {
    strongSignals.push('관리자 그룹 추가 직후 권한 명령');
  }
  if (isMultiAccountGroupAddition(alert, description, groupSignal)) {
    strongSignals.push('같은 주소에서 여러 계정을 관리자 그룹에 추가');
  }
  if (groupSignal && offHoursSignal
      && hasTechnique(alert, 'T1068') && hasTechnique(alert, 'T1078')) {
    strongSignals.push('관리자 그룹 추가와 시간 외 사용 및 T1068·T1078');
  }

  if (strongSignals.length > 0) {
    const confidence = 0.9;
    return {
      action: actionFor(confidence),
      confidence,
      reason: `${[...names, ...strongSignals].join('; ')}: 여러 독립 신호가 일치함`,
    };
  }

  if (names.length > 0) {
    const confidence = names.length > 1
      ? 0.8
      : Math.max(...matchedPatterns.map((pattern) => pattern.confidence));
    return {
      action: actionFor(confidence),
      confidence,
      reason: `${names.join(', ')}: 단일 또는 불완전한 의심 신호`,
    };
  }

  if (hasAmbiguousPrivilegeActivity(alert, description)) {
    const confidence = 0.6;
    return {
      action: actionFor(confidence),
      confidence,
      reason: 'T1068 및 설명에 권한 명령·변경 시도가 있으나 확인 신호가 부족함',
    };
  }

  const confidence = 0.1;
  return {
    action: actionFor(confidence),
    confidence,
    reason: '일치 패턴 없음: 현재 경보 필드에서 권한 악용 근거가 부족함',
  };
}
