const PATTERNS = Object.freeze({
  sql: Object.freeze({
    name: 'SQL 주입 의심 표기',
    strongDescriptions: Object.freeze([
      'SQL 구문을 이어 붙인 요청',
      'SQL 구문 표기',
      '데이터베이스 조회를 이어 붙이는 표기',
    ]),
    weakDescriptions: Object.freeze(['SQL 표식']),
    urlMarkers: Object.freeze(['doc-sql-']),
  }),
  script: Object.freeze({
    name: '스크립트 주입 의심 표식',
    descriptions: Object.freeze(['스크립트 삽입 표기', '스크립트 표식']),
    urlMarkers: Object.freeze(['doc-script-marker', 'doc-mixed-marker']),
  }),
  traversal: Object.freeze({
    name: '반복 경로 탐색 표기',
    descriptions: Object.freeze(['경로를 여러 단계 거슬러', '경로 이탈 표기']),
    urlMarkers: Object.freeze(['doc-up-repeat']),
  }),
  uncertain: Object.freeze({
    name: '미확인 주입 흔적',
    descriptions: Object.freeze([
      '따옴표가 한 번',
      '이상한 검색 1건',
      '주입처럼 보이는 표기',
      '명령 구분자 표기',
      '구분 문자가 1건',
    ]),
    urlMarkers: Object.freeze(['doc-one-fragment', 'doc-one-marker', 'doc-cmd-separator']),
  }),
});

function containsAny(value, fragments) {
  return fragments.some((fragment) => value.includes(fragment));
}

function makeDecision(confidence, reason) {
  const action = confidence >= 0.85
    ? 'block'
    : confidence >= 0.5
      ? 'alert'
      : 'record';
  return { action, confidence, reason: reason.replace(/[\r\n]+/g, ' ') };
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const hasSqlMarker = containsAny(description, PATTERNS.sql.strongDescriptions)
    || containsAny(description, PATTERNS.sql.weakDescriptions)
    || containsAny(url, PATTERNS.sql.urlMarkers);
  const hasStrongSqlEvidence = containsAny(description, PATTERNS.sql.strongDescriptions)
    && Number.isFinite(count) && count >= 10
    && Number.isFinite(level) && level >= 10;

  if (hasStrongSqlEvidence) {
    return makeDecision(0.9, `${PATTERNS.sql.name}: 설명에 반복된 SQL 구문 연결 표식이 기록됨`);
  }

  if (hasSqlMarker) {
    return makeDecision(0.65, `${PATTERNS.sql.name}: 수업용 표식만으로 실제 구문은 확인되지 않음`);
  }

  const hasScriptMarker = containsAny(description, PATTERNS.script.descriptions)
    || containsAny(url, PATTERNS.script.urlMarkers);
  if (hasScriptMarker) {
    return makeDecision(0.65, `${PATTERNS.script.name}: 실제 HTML script 태그는 확인되지 않음`);
  }

  const hasTraversalMarker = containsAny(description, PATTERNS.traversal.descriptions)
    || containsAny(url, PATTERNS.traversal.urlMarkers);
  if (hasTraversalMarker) {
    return makeDecision(0.65, `${PATTERNS.traversal.name}: 수업용 표식만 있고 실제 ../ 구간은 확인되지 않음`);
  }

  const hasUncertainMarker = containsAny(description, PATTERNS.uncertain.descriptions)
    || containsAny(url, PATTERNS.uncertain.urlMarkers);
  if (hasUncertainMarker) {
    return makeDecision(0.58, `${PATTERNS.uncertain.name}: 단일 또는 불명확한 표식`);
  }

  return makeDecision(0.1, '일치 패턴 없음: 정상 또는 근거 부족');
}
