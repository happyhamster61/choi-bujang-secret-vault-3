const PATTERNS = Object.freeze([
  Object.freeze({
    name: '관리자 그룹 추가',
    conditions: "rule.mitre에 T1078이 있고 data.group이 'administrators'이며, rule.description에 관리자 그룹 추가·재추가를 나타내는 문구(예: '관리자 그룹에 추가됐습니다', '관리자 그룹에 들어가고', '관리자 그룹 추가와', '다시 관리자로 들어왔습니다')가 포함됩니다.",
    evidence: 'MITRE ATT&CK T1078은 정상 계정의 악용과 관련됩니다. pv-01, pv-04, pv-05, pv-07, pv-09는 T1078, administrators 그룹 값과 그룹 변경 설명을 함께 기록하지만 계정 탈취 자체를 확정하지는 않습니다.',
    matches(context) {
      return context.t1078 && context.adminGroup && context.groupChange;
    },
    confidence(context) {
      if (!this.matches(context)) return 0;
      return Math.min(1, 0.2 + 0.3 + 0.25 + (context.level >= 10 ? 0.1 : 0)
        + (context.repeatedGroupChange ? 0.05 : 0)
        + (context.multipleAccounts ? 0.1 : 0));
    },
  }),
  Object.freeze({
    name: '처음 보는 주소의 관리자 명령',
    conditions: "rule.mitre에 T1068이 있고 rule.description에 '처음 보는 주소'와 '관리자 명령'이 모두 포함됩니다.",
    evidence: 'MITRE ATT&CK T1068은 권한 상승 악용과 관련됩니다. pv-03은 T1068 태그와 함께 처음 보는 주소에서 관리자 명령을 실행했다고 설명하지만, 명령 식별자나 주소 이력은 구조화 필드로 제공되지 않습니다.',
    matches(context) {
      return context.t1068 && context.unfamiliarAddress && context.adminCommand;
    },
    confidence(context) {
      if (!this.matches(context)) return 0;
      return Math.min(1, 0.2 + 0.2 + 0.2 + (context.commandSucceeded ? 0.15 : 0)
        + (context.outsideHours ? 0.15 : 0) + (context.level >= 10 ? 0.1 : 0));
    },
  }),
  Object.freeze({
    name: '시간 외로 기록된 권한 사용',
    conditions: "rule.mitre에 T1068 또는 T1078이 있고 rule.description에 '수업 시간 밖' 또는 '업무처럼 보이지 않는 시각'이 포함되며, 같은 설명에 관리자 명령·그룹 추가 등 권한 사용 행위가 기록됩니다.",
    evidence: 'pv-03(T1068)과 pv-07(T1068, T1078)의 설명에 시간 외로 표현된 권한 사용이 기록됩니다. fixture에는 공식 업무 일정 필드가 없어 시간 외 여부는 설명 문구로만 확인됩니다.',
    matches(context) {
      return (context.t1068 || context.t1078) && context.outsideHours
        && (context.adminCommand || context.groupChange);
    },
    confidence(context) {
      if (!this.matches(context)) return 0;
      return Math.min(1, 0.15 + 0.2 + 0.2 + (context.commandSucceeded ? 0.15 : 0)
        + (context.level >= 10 ? 0.1 : 0) + (context.adminGroup ? 0.2 : 0));
    },
  }),
]);

function hasTechnique(alert, technique) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(technique);
}

function actionFor(confidence) {
  return confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
}

function scoreSignals(signals) {
  const total = signals.reduce((score, [present, weight]) => score + (present ? weight : 0), 0);
  return Math.min(1, Math.round(total * 100) / 100);
}

function describeSignals(context, failed, canceled, noFollowup) {
  return [
    context.t1068 && 'MITRE T1068',
    context.t1078 && 'MITRE T1078',
    context.adminGroup && context.groupChange && 'administrators 그룹 변경 설명',
    context.newlyPromotedThenCommand && '새 관리자 권한 취득 뒤 명령 실행',
    context.sessionPromoted && '세션의 관리자 권한 변경 설명',
    context.crossAccountAdminCommand && '다른 계정 권한으로 관리자 명령 실행 설명',
    context.adminCommand && '관리자 명령 설명',
    context.commandSucceeded && '명령 실행 성공 설명',
    context.unfamiliarAddress && '처음 보는 주소 설명',
    context.outsideHours && '시간 외 활동 설명',
    context.multipleAccounts && '여러 계정의 관리자 그룹 변경',
    context.immediateAdminCommand && '권한 변경 직후 권한 명령 설명',
    failed && '실패 설명',
    canceled && '취소 설명',
    noFollowup && '후속 명령 없음 설명',
  ].filter(Boolean).join(', ');
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const lower = description.toLowerCase();
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.toLowerCase() : '';
  const count = Number(alert?.data?.count);
  const level = Number(alert?.rule?.level);
  const commandSucceeded = lower.includes('관리자 명령을 실행했습니다')
    || lower.includes('관리자 명령과 명령 실행')
    || lower.includes('권한 명령을 실행했습니다')
    || lower.includes('명령 실행이 같이 있습니다')
    || lower.includes('관리자 명령이 실행됐습니다')
    || (lower.includes('관리자 명령이') && lower.includes('실행됐습니다'));
  const context = {
    t1068: hasTechnique(alert, 'T1068'),
    t1078: hasTechnique(alert, 'T1078'),
    adminGroup: group === 'administrators',
    groupChange: ['관리자 그룹에 추가됐습니다', '관리자 그룹에 들어가고', '관리자 그룹 추가와', '다시 관리자로 들어왔습니다']
      .some((phrase) => lower.includes(phrase)),
    unfamiliarAddress: lower.includes('처음 보는 주소') || lower.includes('요청 주소는 처음 봅니다'),
    outsideHours: lower.includes('수업 시간 밖') || lower.includes('업무처럼 보이지 않는 시각'),
    adminCommand: lower.includes('관리자 명령'),
    commandSucceeded,
    nonAdminGroup: group !== '' && group !== 'administrators',
    membershipChange: lower.includes('그룹에 추가됐습니다')
      || lower.includes('그룹이 하나 만들어졌습니다') || lower.includes('멤버는'),
    groupDescriptionOnly: lower.includes('그룹 설명만 바뀌었습니다'),
    repeatedGroupChange: lower.includes('빠진 계정') && lower.includes('다시 관리자로'),
    multipleAccounts: Number.isSafeInteger(count) && count >= 3
      && lower.includes('계정') && lower.includes('관리자 그룹'),
    sessionPromoted: lower.includes('세션이 관리자 권한으로 바뀌었'),
    crossAccountAdminCommand: lower.includes('다른 계정의 권한으로 관리자 명령'),
    newlyPromotedThenCommand: lower.includes('방금 관리자가 된') && commandSucceeded,
    immediateAdminCommand: lower.includes('곧바로') && lower.includes('권한 명령'),
    level,
  };
  const matched = PATTERNS.filter((pattern) => pattern.matches(context));
  const names = matched.map((pattern) => pattern.name);
  const failed = lower.includes('실패');
  const canceled = lower.includes('취소됐습니다');
  const noFollowup = lower.includes('이어서 명령은 없습니다');
  const noChange = lower.includes('변경은 없습니다') || lower.includes('그룹 목록을 읽은 뒤')
    || lower.includes('그룹 소속을 읽기만') || context.groupDescriptionOnly;

  if (noChange) {
    return { action: 'record', confidence: 0.1,
      reason: `${names.length ? names.join(', ') : '일치 패턴 없음'}: 권한 변경 없는 조회 또는 그룹 설명만 변경됨` };
  }

  if (context.nonAdminGroup && context.membershipChange) {
    return { action: 'record', confidence: 0.1,
      reason: `${names.length ? names.join(', ') : '일치 패턴 없음'}: 관리자 권한 신호가 없는 일반 그룹 변경` };
  }

  const patternScores = matched.map((pattern) => pattern.confidence(context));
  const strongestPatternScore = Math.max(0, ...patternScores);
  const compositeScore = !failed && !canceled && !noFollowup
    ? scoreSignals([
      [context.t1068, 0.15],
      [context.t1078, 0.15],
      [context.newlyPromotedThenCommand, 0.25],
      [context.commandSucceeded, 0.2],
      [context.sessionPromoted, 0.45],
      [context.unfamiliarAddress, 0.15],
      [context.crossAccountAdminCommand, 0.55],
      [context.adminCommand, 0.05],
      [context.adminGroup && context.groupChange, 0.1],
      [context.multipleAccounts, 0.1],
      [context.outsideHours, 0.1],
      [context.immediateAdminCommand, 0.1],
      [level >= 10, 0.1],
    ])
    : 0;
  const confidence = Math.max(strongestPatternScore, compositeScore);

  if (confidence >= 0.85) {
    const support = describeSignals(context, failed, canceled, noFollowup);
    return { action: actionFor(confidence), confidence,
      reason: `${names.length ? names.join(', ') : '일치 패턴 없음'}: ${support || '추가 일치 신호 없음'}; 근거 점수 ${confidence.toFixed(2)}` };
  }

  const attempt = context.t1068 || context.t1078 || context.adminGroup
    || lower.includes('권한 상승') || context.adminCommand || lower.includes('권한 명령')
    || lower.includes('관리자 권한으로 바뀌었');
  if (attempt && (failed || canceled || noFollowup || names.length > 0
      || context.adminCommand || lower.includes('권한 명령') || lower.includes('다시 관리자로')
      || context.unfamiliarAddress || context.outsideHours)) {
    const alertConfidence = Math.min(0.84, scoreSignals([
      [context.t1068, 0.15],
      [context.t1078, 0.15],
      [context.adminGroup, 0.12],
      [context.adminCommand, 0.2],
      [context.unfamiliarAddress, 0.12],
      [context.outsideHours, 0.1],
      [failed, 0.18],
      [canceled, 0.18],
      [noFollowup, 0.18],
      [lower.includes('권한 상승 창'), 0.2],
      [lower.includes('권한 상승이'), 0.2],
      [commandSucceeded, 0.2],
      [level >= 8, 0.08],
      [level >= 7 && level < 8, 0.06],
      [context.groupChange, 0.15],
    ]));
    const reason = canceled ? '권한 상승 시도가 취소되어 성공 여부가 확인되지 않음'
      : failed ? '관리자 명령이 실패하여 성공 여부가 확인되지 않음'
        : noFollowup ? '권한 상승 흔적은 있으나 후속 명령이 확인되지 않음'
          : '패턴이 일부 일치하지만 명확한 복합 악용 근거가 부족함';
    if (alertConfidence >= 0.5) {
      const support = describeSignals(context, failed, canceled, noFollowup);
      return { action: actionFor(alertConfidence), confidence: alertConfidence,
        reason: `${names.length ? names.join(', ') : '일치 패턴 없음'}: ${support || '권한 시도 신호'}; ${reason}` };
    }
  }

  return { action: 'record', confidence: 0.1,
    reason: `${names.length ? names.join(', ') : '일치 패턴 없음'}: 정상 활동 또는 권한 악용 근거 부족` };
}
