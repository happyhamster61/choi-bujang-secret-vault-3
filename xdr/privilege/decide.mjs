function hasTechnique(alert, technique) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(technique);
}

function actionFor(confidence) {
  return confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const lower = description.toLowerCase();
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.toLowerCase() : '';
  const adminGroup = group === 'administrators';
  const t1068 = hasTechnique(alert, 'T1068');
  const t1078 = hasTechnique(alert, 'T1078');
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);

  const nonAdminGroup = group !== '' && !adminGroup
    && (lower.includes('관리자 그룹은 아닙니다') || lower.includes('과제 그룹')
      || lower.includes('새 로컬 그룹'));
  const noChangeOrReadOnly = lower.includes('변경은 없습니다')
    || lower.includes('그룹 목록을 읽은 뒤')
    || lower.includes('그룹 소속을 읽기만');
  if (nonAdminGroup || noChangeOrReadOnly) {
    return { action: 'record', confidence: 0.1, reason: '명시적인 비관리자 그룹 작업 또는 권한 변경 없는 조회' };
  }

  const canceled = lower.includes('취소됐습니다');
  const failed = lower.includes('실패');
  const noFollowup = lower.includes('이어서 명령은 없습니다');
  const successfulAdminCommand = lower.includes('관리자 명령을 실행했습니다')
    || lower.includes('관리자 명령과 명령 실행')
    || lower.includes('권한 명령을 실행했습니다')
    || lower.includes('명령 실행이 같이 있습니다')
    || lower.includes('관리자 명령이 실행됐습니다');
  const groupAdded = adminGroup && t1078 && (
    lower.includes('관리자 그룹에 추가됐습니다')
    || lower.includes('관리자 그룹에 들어가고')
    || lower.includes('관리자 그룹 추가와')
    || lower.includes('다시 관리자로 들어왔습니다')
  );
  const unfamiliarAddress = lower.includes('처음 보는 주소')
    || lower.includes('요청 주소는 처음 봅니다');
  const sessionPromoted = lower.includes('세션이 관리자 권한으로 바뀌었');
  const otherAccountCommand = lower.includes('다른 계정의 권한으로 관리자 명령');
  const outsideHours = lower.includes('수업 시간 밖')
    || lower.includes('업무처럼 보이지 않는 시각');
  const repeatedGroupChange = lower.includes('빠진 계정') && lower.includes('다시 관리자로');
  const multiAccountChange = Number.isSafeInteger(count) && count >= 3
    && lower.includes('같은 주소') && lower.includes('관리자 그룹');

  if (!canceled && !failed && !noFollowup && (
    (t1068 && t1078 && lower.includes('방금 관리자가 된') && successfulAdminCommand)
    || (groupAdded && lower.includes('곧바로') && lower.includes('권한 명령'))
    || (t1068 && sessionPromoted && unfamiliarAddress && level >= 10)
    || (t1068 && otherAccountCommand && level >= 10)
    || (groupAdded && successfulAdminCommand && outsideHours && t1068 && level >= 10)
    || (multiAccountChange && t1078 && level >= 10)
    || (repeatedGroupChange && groupAdded && t1078 && level >= 10)
    || (t1068 && unfamiliarAddress && successfulAdminCommand && outsideHours && level >= 10)
  )) {
    return {
      action: 'block',
      confidence: 0.9,
      reason: '성공한 권한 변경 또는 관리자 권한 사용과 추가 위험 신호가 함께 확인됨',
    };
  }

  const privilegeAttempt = t1068 || t1078 || adminGroup
    || lower.includes('권한 상승') || lower.includes('관리자 명령')
    || lower.includes('권한 명령') || lower.includes('관리자 권한으로 바뀌었');
  if (privilegeAttempt && (canceled || failed || noFollowup
      || groupAdded || sessionPromoted || otherAccountCommand
      || lower.includes('관리자 명령') || lower.includes('권한 명령')
      || lower.includes('다시 관리자로') || outsideHours)) {
    const reason = canceled ? '권한 상승 요청이 취소되어 시도만 확인됨'
      : failed ? '관리자 명령 실패로 성공 여부가 확인되지 않음'
        : noFollowup ? '권한 상승 흔적은 있으나 후속 명령이 확인되지 않음'
          : '권한 관련 시도 또는 단일 변경 신호가 있으나 확정 근거가 부족함';
    return { action: 'alert', confidence: 0.6, reason };
  }

  return { action: 'record', confidence: 0.1, reason: '권한 악용 신호가 확인되지 않음' };
}
