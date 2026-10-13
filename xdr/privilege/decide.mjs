const PATTERNS = Object.freeze([
  {
    name: '관리자 그룹에 계정 추가',
    mitre: ['T1078'],
    matches: ({ alert, description, techniques }) =>
      alert?.data?.group === 'administrators'
      && techniques.includes('T1078')
      && /관리자 그룹.{0,24}(?:추가|들어|재추가)|다시 관리자(?:로| 그룹에).{0,12}들어/.test(description),
  },
  {
    name: '처음 보는 주소에서 관리자 명령 실행',
    mitre: ['T1068'],
    matches: ({ description, techniques }) =>
      techniques.includes('T1068')
      && /처음\s*보는\s*주소/.test(description)
      && /관리자\s*명령.{0,24}실행/.test(description),
  },
  {
    name: '업무 시간 외 관리자 권한 사용',
    mitre: ['T1068', 'T1078'],
    matches: ({ description, techniques, timestampValid, adminGroupChange, adminCommand }) =>
      techniques.some((technique) => ['T1068', 'T1078'].includes(technique))
      && timestampValid
      && /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각/.test(description)
      && (adminGroupChange || adminCommand),
  },
]);

const BLOCK_THRESHOLD = 0.85;
const ALERT_THRESHOLD = 0.5;

function oneLine(value) {
  return typeof value === 'string' ? value.replace(/[\r\n]+/g, ' ').trim() : '';
}

function levelOf(alert) {
  const level = alert?.rule?.level;
  if (typeof level === 'number' && Number.isFinite(level)) return level;
  if (typeof level === 'string' && level.trim() !== '' && Number.isFinite(Number(level))) {
    return Number(level);
  }
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
  const timestampValid = typeof alert?.timestamp === 'string'
    && Number.isFinite(Date.parse(alert.timestamp));
  const techniques = Array.isArray(alert?.rule?.mitre)
    ? alert.rule.mitre.filter((technique) => typeof technique === 'string')
    : [];
  const level = levelOf(alert);
  const group = oneLine(alert?.data?.group).toLowerCase();
  const adminGroupChange = group === 'administrators'
    && /관리자 그룹.{0,24}(?:추가|들어|재추가)|다시 관리자(?:로| 그룹에).{0,12}들어/.test(description);
  const adminCommand = /관리자\s*명령.{0,24}(?:실행|실패)|권한\s*명령.{0,24}실행/.test(description)
    || (adminGroupChange && /명령\s*실행/.test(description));
  const context = { alert, description, techniques, timestampValid, adminGroupChange, adminCommand };
  const matched = PATTERNS.filter((pattern) => pattern.matches(context));

  if (!description || level === null || !account || !timestampValid) {
    return result(0, '시각, 계정, 설명 또는 규칙 수준이 없어 패턴 근거를 확인할 수 없습니다.');
  }

  const reasons = [];
  let confidence = 0;

  if (matched.length > 0) {
    const scores = matched.map((pattern) => {
      reasons.push(pattern.name);
      if (pattern.name === '관리자 그룹에 계정 추가') return 0.69;
      if (pattern.name === '처음 보는 주소에서 관리자 명령 실행') return 0.76;
      return 0.65;
    });
    confidence = Math.max(...scores);

    // A recorded admin-group change followed by command execution, or a repeated/bulk
    // membership change, provides stronger corroboration than the pattern alone.
    const count = Number(alert?.data?.count);
    const repeatedOrBulk = Number.isFinite(count) && count > 1
      || /계정\s*\d+개|다시\s*관리자|1분\s*뒤에\s*다시/.test(description);
    if (adminGroupChange && adminCommand) confidence += 0.21;
    else if (adminGroupChange && repeatedOrBulk) confidence += 0.18;

    // High rule level is only a small corroborating factor after a pattern matched.
    if (level >= 10) confidence += 0.03;

    // The first-seen-address and out-of-hours claims are description-only and cannot
    // independently turn an uncertain event into a block.
    if (matched.some((pattern) => pattern.name === '처음 보는 주소에서 관리자 명령 실행')
        && matched.some((pattern) => pattern.name === '업무 시간 외 관리자 권한 사용')) {
      confidence = Math.min(confidence, 0.84);
    }
  } else {
    const hasPrivilegeTechnique = techniques.some((technique) => ['T1068', 'T1078'].includes(technique));
    const unusualAddress = /처음\s*보는\s*주소|요청\s*주소는\s*처음/.test(description);
    const otherAccount = /다른\s*계정의\s*권한/.test(description);
    const changedToAdmin = /세션이\s*관리자\s*권한으로\s*바뀌|방금\s*관리자가\s*된/.test(description);
    const attemptedElevation = /권한\s*상승/.test(description);
    const cancelled = /취소됐|취소\s*되었습니다/.test(description);
    const failedCommand = /관리자\s*명령.{0,24}실패/.test(description);
    const noFollowOnCommand = /권한\s*상승.{0,24}명령은\s*없|이어s*명령은\s*없/.test(description);
    const routineAddress = /평소\s*주소/.test(description);

    if (hasPrivilegeTechnique && adminCommand && (otherAccount || changedToAdmin || unusualAddress || failedCommand)) {
      confidence = otherAccount ? 0.73 : changedToAdmin && unusualAddress ? 0.78 : 0.61;
      reasons.push(otherAccount ? '다른 계정 권한으로 관리자 명령 실행' : '관리자 명령의 불완전한 의심 신호');
    } else if (hasPrivilegeTechnique && changedToAdmin && unusualAddress) {
      confidence = 0.76;
      reasons.push('처음 보는 주소의 관리자 권한 세션 변경');
    } else if (hasPrivilegeTechnique && attemptedElevation && (cancelled || noFollowOnCommand)) {
      confidence = cancelled ? 0.58 : 0.62;
      reasons.push(cancelled ? '취소된 권한 상승 시도' : '후속 관리자 명령이 없는 권한 상승 단서');
    } else if (hasPrivilegeTechnique && adminCommand && routineAddress) {
      confidence = 0.2;
      reasons.push('평소 주소의 단발 관리자 명령이며 추가 이상 단서는 확인되지 않음');
    }
  }

  if (reasons.length === 0) {
    return result(0.05, '세 패턴과 일치하는 권한 상승 근거가 없어 일반 이벤트로 기록합니다.');
  }

  const uncertainty = matched.some((pattern) =>
    pattern.name === '처음 보는 주소에서 관리자 명령 실행'
      || pattern.name === '업무 시간 외 관리자 권한 사용')
    ? '이력·업무 시간 기준은 설명에만 있어 독립 확인되지 않았습니다.'
    : '설명과 구조화된 그룹 필드에서 확인되는 신호를 사용했습니다.';
  return result(confidence, `${reasons.join(', ')}: ${uncertainty}`);
}
