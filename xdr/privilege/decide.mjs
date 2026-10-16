const PATTERNS = Object.freeze([
  Object.freeze({
    name: '관리자 그룹에 계정 추가',
    condition: "data.group이 'administrators'이고 rule.description에 계정이 관리자 그룹에 추가되거나 다시 추가됐다는 내용이 기록된 경우",
    mitre: Object.freeze(['T1078']),
    evidence: 'fixture는 data.group과 T1078 태그를 제공하고 설명에 관리자 그룹 추가·재추가를 기록하지만, 변경 승인 여부나 실제 권한 사용은 별도로 제공하지 않습니다.',
    evaluate(context) {
      if (context.adminGroupChange && context.hasTechnique('T1078')) {
        return { strength: 'full', evidence: 'administrators 그룹 필드, T1078, 추가 설명이 일치' };
      }
      if (context.hasTechnique('T1078') && context.adminPrivilegeTransition && !context.explicitNonAdminGroup) {
        return { strength: 'partial', evidence: '관리자 권한 취득 설명은 있지만 administrators 그룹 필드가 없음' };
      }
      return null;
    },
  }),
  Object.freeze({
    name: '처음 관찰되는 관리자 명령 실행',
    condition: 'rule.description이 관리자 명령 자체가 처음 관찰되었거나 처음 실행되었다고 명시하고 rule.mitre에 T1068이 포함된 경우. 주소나 출발 IP가 처음이라는 내용만으로는 일치하지 않음',
    mitre: Object.freeze(['T1068']),
    evidence: 'fixture에는 data.srcip은 있지만 관리자 명령의 이름이나 과거 실행 이력은 없으므로, 설명이 명령 자체의 최초 관찰·실행을 명시할 때만 신호로 삼고 이력은 독립 검증할 수 없습니다.',
    evaluate(context) {
      if (context.hasTechnique('T1068') && context.firstObservedAdminCommand) {
        return { strength: 'full', evidence: 'T1068과 관리자 명령 자체의 최초 관찰 설명이 일치' };
      }
      if (context.hasTechnique('T1068')
        && (context.adminCommand || context.adminPrivilegeTransition || context.attemptedElevation)) {
        const evidence = context.adminCommand
          ? 'T1068과 관리자 명령 실행이 있으나 명령의 최초 관찰은 확인되지 않음'
          : context.adminPrivilegeTransition
            ? 'T1068과 관리자 세션 권한 변경 설명은 있으나 명령 실행은 없음'
            : 'T1068과 권한 상승 시도는 있으나 관리자 명령 실행은 없음';
        return { strength: 'partial', evidence };
      }
      return null;
    },
  }),
  Object.freeze({
    name: '업무 시간 외 관리자 권한 사용',
    condition: 'rule.description에 수업 시간 밖 또는 업무처럼 보이지 않는 시각이라는 단서와 관리자 그룹 변경 또는 관리자 명령 실행이 함께 기록된 경우',
    mitre: Object.freeze(['T1068', 'T1078']),
    evidence: 'fixture에는 timestamp와 시간 외라는 설명이 있지만 공식 업무·수업 시간 정책은 없어 시간 외 여부는 설명의 주장으로만 확인됩니다.',
    evaluate(context) {
      const relevantTechnique = context.hasTechnique('T1068') || context.hasTechnique('T1078');
      if (relevantTechnique && context.timestampValid && context.outsideHours
        && (context.adminGroupChange || context.adminCommandExecuted)) {
        return { strength: 'full', evidence: '유효한 시각, 시간 외 설명, 관리자 권한 행위가 함께 기록됨' };
      }
      if (relevantTechnique && context.timestampValid && context.outsideHours
        && context.adminPrivilegeTransition) {
        return { strength: 'partial', evidence: '시간 외 설명과 관리자 세션 변경은 있으나 그룹 변경·명령 실행이 없음' };
      }
      return null;
    },
  }),
  Object.freeze({
    name: '권한·그룹 변경 확인 필요',
    condition: "T1078 태그, rule.level 5~9, 계정·그룹의 조회·추가·생성·설명 변경 단서가 함께 있는 경우 관리자 그룹이 아니어도 확인 필요 알림으로 둡니다. 태그나 수준만으로 차단하지 않습니다.",
    mitre: Object.freeze(['T1078']),
    evidence: "T1078은 정상 계정의 악용을 다루며, 이 실습의 중간 수준 계정·그룹 경보는 승인 여부와 공격 성공이 확인되지 않아 alert로만 남깁니다. MITRE 태그 자체가 공격 성공을 증명하지는 않습니다.",
    evaluate(context) {
      return context.hasTechnique('T1078') && context.accountManagementReview
        ? { strength: 'partial', evidence: '중간 수준 T1078 계정·그룹 관리 경보' } : null;
    },
  }),
]);

const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function oneLine(value) {
  return typeof value === 'string' ? value.replace(/[\r\n]+/g, ' ').trim() : '';
}

function levelOf(alert) {
  const level = alert?.rule?.level;
  if (typeof level === 'number' && Number.isFinite(level)) return level;
  if (typeof level === 'string' && level.trim() !== '' && Number.isFinite(Number(level))) return Number(level);
  return null;
}

function result(confidence, reason) {
  const bounded = Math.max(0, Math.min(1, confidence));
  const action = bounded >= BLOCK_THRESHOLD ? 'block' : bounded >= ALERT_THRESHOLD ? 'alert' : 'record';
  return { action, confidence: Number(bounded.toFixed(2)), reason: oneLine(reason) };
}

export function decide(alert) {
  const description = oneLine(alert?.rule?.description);
  const account = oneLine(alert?.data?.srcuser);
  const timestampValid = typeof alert?.timestamp === 'string' && Number.isFinite(Date.parse(alert.timestamp));
  const level = levelOf(alert);
  const rawTechniques = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre : alert?.rule?.mitre?.id;
  const techniques = Array.isArray(rawTechniques)
    ? rawTechniques.filter(technique => typeof technique === 'string')
      .map(technique => technique.trim().toUpperCase()) : [];
  const group = oneLine(alert?.data?.group).toLowerCase();
  const adminGroupChange = group === 'administrators'
    && /관리자 그룹.{0,24}(?:추가|들어|재추가)|다시 관리자(?:로| 그룹에).{0,12}들어/.test(description);
  const explicitNonAdminGroup = group !== '' && group !== 'administrators'
    && /관리자 그룹은 아닙니다|관리자 그룹이 아닌/.test(description);
  const adminCommand = /관리자\s*명령.{0,24}(?:실행|실패)|권한\s*명령.{0,24}실행/.test(description)
    || (adminGroupChange && /명령\s*실행/.test(description));
  const adminCommandExecuted = /관리자\s*명령.{0,24}실행|권한\s*명령.{0,24}실행/.test(description)
    || (adminGroupChange && /명령\s*실행/.test(description));
  const adminPrivilegeTransition = /방금\s*관리자가\s*된|세션이\s*관리자\s*권한으로\s*바뀌/.test(description);
  const firstObservedAdminCommand = /처음\s*(?:관찰|실행)(?:된|되는|한|됨|됐|되었습니다)\s*관리자\s*명령|관리자\s*명령(?:이|은|을)?\s*처음\s*(?:관찰|실행)(?:됐|되었|되는|됩니다|되었습니다|됨|했습니다|한)/.test(description);
  const attemptedElevation = /권한\s*상승/.test(description);
  const outsideHours = /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각/.test(description);
  const context = {
    adminGroupChange,
    accountManagementReview: level >= 5 && level < 10
      && /계정|그룹|account|group/i.test(description),
    explicitNonAdminGroup,
    adminCommand,
    adminCommandExecuted,
    adminPrivilegeTransition,
    firstObservedAdminCommand,
    attemptedElevation,
    outsideHours,
    timestampValid,
    hasTechnique: (technique) => techniques.includes(technique),
  };

  if (!description || level === null || !account || !timestampValid) {
    return result(0, '필수 경보 필드가 없어 세 패턴을 평가할 수 없습니다.');
  }

  const matches = PATTERNS.map((pattern) => {
    const match = pattern.evaluate(context);
    return match ? { pattern, ...match } : null;
  }).filter(Boolean);

  if (matches.length === 0) {
    return result(0.05, '세 패턴과 일치하거나 부분 일치하는 근거가 없어 정상 이벤트로 기록합니다.');
  }

  const fullMatches = matches.filter((match) => match.strength === 'full');
  const partialMatches = matches.filter((match) => match.strength === 'partial');
  const strongest = Math.max(...fullMatches.map(({ pattern }) => {
    if (pattern.name === '관리자 그룹에 계정 추가') return 0.88;
    if (pattern.name === '처음 관찰되는 관리자 명령 실행') return 0.78;
    return 0.83;
  }), ...partialMatches.map(() => 0.58));

  let confidence = strongest;
  const supportingEvidence = [];
  confidence += Math.max(0, fullMatches.length - 1) * 0.04;
  confidence += Math.max(0, partialMatches.length - (fullMatches.length ? 0 : 1)) * 0.04;
  if (level >= 10) {
    confidence += 0.02;
    supportingEvidence.push(`rule.level ${level} 보조 신호`);
  }

  const otherAccountPrivilege = /다른\s*계정의\s*권한/.test(description);
  const unfamiliarAddress = /처음\s*보는\s*주소|요청\s*주소는\s*처음\s*봅니다/.test(description);
  const routineAddress = /평소\s*주소/.test(description);
  const cancelled = /취소됐|취소\s*되었습니다/.test(description);
  const failedCommand = /관리자\s*명령.{0,24}실패/.test(description);
  const noFollowOnCommand = /권한\s*상승.{0,24}명령은\s*없|이어서\s*명령은\s*없/.test(description);
  if (otherAccountPrivilege) {
    confidence += 0.03;
    supportingEvidence.push('다른 계정의 권한 사용');
  }
  if (unfamiliarAddress) {
    confidence += 0.02;
    supportingEvidence.push('처음 관찰된 출발 주소');
  }
  if (routineAddress) {
    confidence -= 0.05;
    supportingEvidence.push('평소 주소라는 설명은 위험도 보정에 반영');
  }
  if (cancelled) {
    confidence -= 0.04;
    supportingEvidence.push('시도 취소');
  }
  if (failedCommand || noFollowOnCommand) {
    confidence -= 0.03;
    supportingEvidence.push(failedCommand ? '명령 실패' : '후속 명령 미관측');
  }

  // Independent high-risk context can corroborate a partial pattern match.
  // A privilege transition followed by an administrator command with both
  // privilege-related ATT&CK tags is stronger than either partial match alone.
  if (adminPrivilegeTransition && adminCommandExecuted
    && context.hasTechnique('T1068') && context.hasTechnique('T1078')) {
    confidence += 0.25;
    supportingEvidence.push('관리자 권한 전환 직후 T1068·T1078 관리자 명령 실행');
  }
  if (adminCommandExecuted && otherAccountPrivilege
    && context.hasTechnique('T1068') && level >= 10) {
    confidence += 0.27;
    supportingEvidence.push('높은 규칙 수준의 다른 계정 권한 관리자 명령');
  }
  if (adminPrivilegeTransition && unfamiliarAddress
    && context.hasTechnique('T1068') && level >= 10) {
    confidence += 0.27;
    supportingEvidence.push('높은 규칙 수준의 낯선 주소 관리자 권한 세션 전환');
  }

  // Partial evidence without corroborating attack context remains an alert.
  if (fullMatches.length === 0
    && !(adminPrivilegeTransition && adminCommandExecuted
      && context.hasTechnique('T1068') && context.hasTechnique('T1078'))
    && !(adminCommandExecuted && otherAccountPrivilege
      && context.hasTechnique('T1068') && level >= 10)
    && !(adminPrivilegeTransition && unfamiliarAddress
      && context.hasTechnique('T1068') && level >= 10)) {
    confidence = Math.min(confidence, 0.84);
  }

  const patternReason = matches.map(({ pattern, strength, evidence }) =>
    `${pattern.name} (${strength === 'full' ? '완전 일치' : '부분 일치'}): ${evidence}`,
  ).join('; ');
  const reason = supportingEvidence.length > 0
    ? `${patternReason}; 보조 근거: ${supportingEvidence.join(', ')}`
    : patternReason;
  return result(confidence, reason);
}
