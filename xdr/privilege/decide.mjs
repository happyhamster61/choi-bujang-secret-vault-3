const PATTERNS = Object.freeze([
  Object.freeze({
    name: '관리자 그룹 추가',
    conditions: "rule.mitre에 T1078이 있고 data.group이 'administrators'이며, rule.description에 관리자 그룹 추가·재추가 문구가 포함됨",
    evidence: 'T1078과 administrators 그룹 값 및 변경 설명을 함께 확인합니다. 그룹 변경만으로 계정 탈취를 확정하지 않습니다.',
    matches(alert, context) {
      return context.t1078 && context.adminGroup && context.groupChange;
    },
  }),
  Object.freeze({
    name: '처음 보는 주소의 관리자 명령',
    conditions: "rule.mitre에 T1068이 있고 rule.description에 처음 보는 주소와 관리자 명령 실행이 함께 기록됨",
    evidence: 'T1068과 설명의 주소·명령 단서를 확인합니다. 주소 이력은 구조화 필드로 제공되지 않습니다.',
    matches(alert, context) {
      return context.t1068 && context.unfamiliarAddress && context.adminCommand;
    },
  }),
  Object.freeze({
    name: '시간 외로 기록된 권한 사용',
    conditions: "rule.mitre에 T1068 또는 T1078이 있고 설명에 시간 외 표현과 관리자 명령 또는 관리자 그룹 변경이 함께 기록됨",
    evidence: 'ATT&CK T1068/T1078 태그와 시간 외 권한 사용 설명을 확인합니다. 공식 일정 필드는 없어 시간 정보는 설명에만 의존합니다.',
    matches(alert, context) {
      return (context.t1068 || context.t1078) && context.outsideHours
        && (context.adminCommand || context.groupChange);
    },
  }),
  Object.freeze({
    name: '비관리자 그룹 멤버 변경',
    conditions: "T1078 또는 그룹 필드와 함께 관리자 이외 그룹의 멤버 추가나 새 그룹·멤버 지정이 설명에 기록됨",
    evidence: '일반 그룹 멤버 변경은 접근 범위에 영향을 줄 수 있지만 관리자 권한 악용이 확인되지 않아 경보로 남깁니다.',
    matches(alert, context) {
      return context.nonAdminGroup && context.membershipChange;
    },
  }),
]);

function hasTechnique(alert, technique) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(technique);
}

function actionFor(confidence) {
  return confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const lower = description.toLowerCase();
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.toLowerCase() : '';
  const context = {
    t1068: hasTechnique(alert, 'T1068'),
    t1078: hasTechnique(alert, 'T1078'),
    adminGroup: group === 'administrators',
    groupChange: ['관리자 그룹에 추가됐습니다', '관리자 그룹에 들어가고', '관리자 그룹 추가와', '다시 관리자로 들어왔습니다']
      .some((phrase) => lower.includes(phrase)),
    unfamiliarAddress: lower.includes('처음 보는 주소') || lower.includes('요청 주소는 처음 봅니다'),
    usualAddress: lower.includes('평소 주소'),
    singleAdminCommand: lower.includes('관리자 명령이 한 번 실행됐습니다'),
    outsideHours: lower.includes('수업 시간 밖') || lower.includes('업무처럼 보이지 않는 시각'),
    adminCommand: lower.includes('관리자 명령'),
    commandSucceeded: lower.includes('관리자 명령을 실행했습니다')
      || lower.includes('관리자 명령과 명령 실행')
      || lower.includes('권한 명령을 실행했습니다')
      || lower.includes('명령 실행이 같이 있습니다')
      || lower.includes('관리자 명령이 실행됐습니다'),
    nonAdminGroup: group !== '' && group !== 'administrators',
    membershipChange: lower.includes('그룹에 추가됐습니다')
      || lower.includes('그룹이 하나 만들어졌습니다')
      || lower.includes('멤버는'),
    groupDescriptionOnly: lower.includes('그룹 설명만 바뀌었습니다'),
  };
  const matched = PATTERNS.filter((pattern) => pattern.matches(alert, context));
  const names = matched.map((pattern) => pattern.name);
  const failed = lower.includes('실패');
  const canceled = lower.includes('취소됐습니다');
  const noFollowup = lower.includes('이어서 명령은 없습니다');
  const noChange = lower.includes('변경은 없습니다') || lower.includes('그룹 목록을 읽은 뒤')
    || lower.includes('그룹 소속을 읽기만') || context.groupDescriptionOnly;

  if (noChange) {
    return { action: 'record', confidence: 0.1,
      reason: '정상 신호: 권한 변경 없는 조회 또는 그룹 설명만 수정' };
  }

  const isolatedRoutineCommand = context.t1068 && context.usualAddress
    && context.singleAdminCommand && !context.unfamiliarAddress && !context.outsideHours
    && !context.adminGroup && !lower.includes('권한 상승')
    && !lower.includes('다른 계정의 권한');
  if (isolatedRoutineCommand) {
    return { action: 'record', confidence: 0.1,
      reason: '정상 신호: 평소 주소의 단발 관리자 명령이며 추가 권한 악용 징후 없음' };
  }

  const nonAdminMembershipPattern = matched.find((pattern) => pattern.name === '비관리자 그룹 멤버 변경');
  if (nonAdminMembershipPattern) {
    const explicitPrivilegeSignal = context.t1068 || context.adminCommand
      || lower.includes('권한 상승') || lower.includes('관리자 권한');
    if (!explicitPrivilegeSignal) {
      return { action: 'record', confidence: 0.1,
        reason: `${nonAdminMembershipPattern.name}: 관리자 권한 상승 신호 없이 일반 그룹만 변경됨` };
    }
    const confidence = 0.6;
    return { action: actionFor(confidence), confidence,
      reason: `${nonAdminMembershipPattern.name}: 그룹 멤버 변경은 있으나 관리자 권한 악용은 불분명함` };
  }

  const adminGroupPattern = matched.find((pattern) => pattern.name === '관리자 그룹 추가');
  if (adminGroupPattern) {
    const confidence = 0.9;
    return { action: actionFor(confidence), confidence,
      reason: `${adminGroupPattern.name}: T1078과 administrators 그룹 변경이 함께 확인됨` };
  }

  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const strongEvidence = !failed && !canceled && !noFollowup && (
    (context.t1068 && context.t1078 && lower.includes('방금 관리자가 된') && context.commandSucceeded)
    || (context.t1078 && context.adminGroup && lower.includes('곧바로') && lower.includes('권한 명령'))
    || (context.t1068 && lower.includes('세션이 관리자 권한으로 바뀌었')
      && context.unfamiliarAddress && level >= 10)
    || (context.t1068 && lower.includes('다른 계정의 권한으로 관리자 명령') && level >= 10)
    || (context.t1078 && context.adminGroup && Number.isSafeInteger(count) && count >= 3
      && lower.includes('같은 주소') && level >= 10)
    || (context.t1068 && context.t1078 && context.adminGroup && context.outsideHours
      && context.commandSucceeded && level >= 10)
    || (context.t1068 && context.unfamiliarAddress && context.commandSucceeded
      && context.outsideHours && level >= 10)
  );

  if (strongEvidence) {
    const confidence = 0.9;
    return { action: actionFor(confidence), confidence,
      reason: `${names.length ? names.join(', ') : '복합 권한 악용 신호'}: 권한 변경·사용과 추가 위험 근거가 함께 확인됨` };
  }

  const attempt = context.t1068 || context.t1078 || context.adminGroup
    || lower.includes('권한 상승') || context.adminCommand || lower.includes('권한 명령')
    || lower.includes('관리자 권한으로 바뀌었');
  if (attempt && (failed || canceled || noFollowup || names.length > 0
      || context.adminCommand || lower.includes('권한 명령') || lower.includes('다시 관리자로')
      || context.unfamiliarAddress || context.outsideHours)) {
    const confidence = names.length > 1 ? 0.8 : names.length === 1 ? 0.68 : 0.6;
    const reason = canceled ? '권한 상승 시도가 취소되어 성공 여부가 확인되지 않음'
      : failed ? '관리자 명령이 실패하여 성공 여부가 확인되지 않음'
        : noFollowup ? '권한 상승 흔적은 있으나 후속 명령이 확인되지 않음'
          : '패턴 신호는 있으나 명확한 복합 악용 근거가 부족함';
    return { action: actionFor(confidence), confidence,
      reason: `${names.length ? names.join(', ') : '애매한 권한 시도'}: ${reason}` };
  }

  return { action: 'record', confidence: 0.1, reason: '일치 패턴 없음: 정상 활동 또는 권한 악용 근거 부족' };
}
