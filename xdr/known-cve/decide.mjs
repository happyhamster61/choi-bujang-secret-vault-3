const PATTERNS = Object.freeze({
  clearLog4Shell: Object.freeze({
    name: 'Log4Shell JNDI 원격 조회 표현식',
    condition: 'data.useragent 또는 data.url에 ${jndi:<protocol>://...} 완전 표현식이 있고 protocol은 ldap, ldaps, rmi, dns 중 하나입니다.',
    evidence: 'known-cve fixture kc-01~kc-08에 ${jndi:ldap://...}가 있으며 CVE-2021-44228은 공격자 제어 JNDI 원격 조회와 관련됩니다.',
  }),
  suspiciousProbe: Object.freeze({
    name: '알려진 취약점 probe 점검 흔적 (의심)',
    condition: 'rule.description에 알려진 취약점 점검 흔적이 있고 data.url의 /health 경로에 probe 매개변수가 있습니다.',
    evidence: 'kc-05에 해당 설명과 /health?probe= 경로가 있으나 특정 스캐너나 User-Agent는 확인되지 않습니다.',
  }),
  weakExploration: Object.freeze({
    name: 'T1190 약한 취약점 탐색 흔적',
    condition: 'rule.mitre에 T1190이 있고 rule.level이 5~8이며, 완전한 JNDI 원격 조회 표현식 없이 경보 설명·요청 주소·User-Agent에 CVE 이름 검색, 단독 jndi, 취약점 목록, 중괄호, 도구 유사 문구, 라이브러리 언급 또는 잘린 조회 흔적이 있습니다.',
    evidence: 'known-cve fixture kc-09~kc-16에 해당하는 약한 흔적과 T1190, 수준 5~8이 있고 완전한 원격 조회 표현식은 없습니다.',
  }),
});

const CONFIDENCE = Object.freeze({
  clear: 0.95,
  suspicious: 0.65,
  none: 0.1,
});

function decision(confidence, reason) {
  const action = confidence >= 0.85
    ? 'block'
    : confidence >= 0.5
      ? 'alert'
      : 'record';
  return { action, confidence, reason: String(reason).replace(/[\r\n]+/g, ' ') };
}

function hasClearJndiLookup(alert) {
  const fields = [alert?.data?.useragent, alert?.data?.url];
  const expression = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns)\s*:\/\/[^}\s]+\}/i;
  return fields.some((value) => typeof value === 'string' && expression.test(value));
}

function hasSuspiciousProbe(alert) {
  const description = alert?.rule?.description;
  const url = alert?.data?.url;
  if (typeof description !== 'string' || typeof url !== 'string') return false;

  const explicitProbeClue = /알려진 취약점 점검 흔적/.test(description);
  const probePath = /^\/health(?:\?|$)/i.test(url)
    && /(?:^|[?&])probe(?:=|&|$)/i.test(url.slice(url.indexOf('?') + 1));
  return explicitProbeClue && probePath;
}

function hasWeakExploration(alert) {
  const mitre = alert?.rule?.mitre;
  const level = alert?.rule?.level;
  if (!Array.isArray(mitre) || !mitre.includes('T1190')
      || !Number.isInteger(level) || level < 5 || level > 8) return false;

  const text = [alert?.rule?.description, alert?.data?.url, alert?.data?.useragent]
    .filter((value) => typeof value === 'string')
    .join(' ')
    .toLocaleLowerCase();
  return /cve-2021-44228|\bjndi\b|취약점 목록|중괄호|점검 도구와 비슷한|라이브러리 이름|조회 형태가 잘린|취약점 이름 검색/.test(text);
}

export function decide(alert) {
  if (hasClearJndiLookup(alert)) {
    return decision(CONFIDENCE.clear, `${PATTERNS.clearLog4Shell.name}: 요청 값에서 완전한 JNDI 원격 조회 표현식을 확인함`);
  }

  if (hasSuspiciousProbe(alert)) {
    return decision(CONFIDENCE.suspicious, `${PATTERNS.suspiciousProbe.name}: 점검 설명과 probe 경로가 있으나 악용 표현식은 확인되지 않음`);
  }

  if (hasWeakExploration(alert)) {
    return decision(CONFIDENCE.suspicious, `${PATTERNS.weakExploration.name}: T1190 및 약한 탐색 흔적은 있으나 완전한 악용 표현식은 확인되지 않음`);
  }

  return decision(CONFIDENCE.none, '일치 패턴 없음: 공격 근거 부족');
}
