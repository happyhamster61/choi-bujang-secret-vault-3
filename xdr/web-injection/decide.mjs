const CLEAR_MARKERS = Object.freeze([
  'SQL 구문',
  '데이터베이스 조회',
  '스크립트 삽입 표기',
  '스크립트 표식',
  '경로를 여러 단계 거슬러',
  '경로 이탈 표기',
  '명령 구분자 표기',
]);

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
  const level = Number(alert?.rule?.level);
  const count = Number(alert?.data?.count);
  const isT1190 = Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.includes('T1190');
  const hasClearMarker = CLEAR_MARKERS.some((marker) => description.includes(marker));
  const isRepeatedHighSignal = isT1190
    && hasClearMarker
    && Number.isFinite(level) && level >= 10
    && Number.isFinite(count) && count >= 8;

  if (isRepeatedHighSignal) {
    return makeDecision(0.9, '반복 주입 표식: T1190 경보의 설명·수준·횟수가 함께 뒷받침함');
  }

  if (isT1190 && Number.isFinite(level) && level >= 5) {
    return makeDecision(0.65, '불명확한 주입 흔적: T1190 경보이나 반복·고수준 근거가 부족함');
  }

  return makeDecision(0.1, '일치 패턴 없음: 정상 또는 근거 부족');
}
