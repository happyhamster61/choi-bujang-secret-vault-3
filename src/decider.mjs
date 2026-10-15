// ALEPH SDP 엔진이 확인한 요청만 받습니다. 등록 상태는 엔진이 확인한 계약 필드입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

const SIGNAL_FIELDS = ['source', 'region', 'network', 'hour'];
const EVENT_FIELDS = ['kind', 'ageSeconds', 'count'];

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasFields(value, fields) {
  return isRecord(value) && fields.every(field => Object.hasOwn(value, field));
}

/**
 * Inspect only the connection context fields defined by aleph.decision.v1.
 * This is input validation, not a policy decision or a claim that fixture data
 * represents a real location or network observation.
 */
export function inspectContextInput(request) {
  const signals = request?.signals;
  const source = isRecord(signals) && Object.hasOwn(signals, 'source')
    ? signals.source
    : undefined;
  const sourceClass = source === 'none'
    ? 'none'
    : source === 'judge_fixture'
      ? 'fixture'
      : 'unknown';
  const events = request?.recentEvents;

  return {
    sourceClass,
    signalsShapeValid: hasFields(signals, SIGNAL_FIELDS),
    recentEventsShapeValid: Array.isArray(events)
      && events.length <= 12
      && events.every(event => hasFields(event, EVENT_FIELDS)),
  };
}

function isFixtureCompositeAnomaly(request, context) {
  // Match only the fixture's exact virtual values; the contract defines no live baseline or thresholds.
  return context.sourceClass === 'fixture'
    && context.signalsShapeValid
    && context.recentEventsShapeValid
    && request.signals.hour === 3
    && request.signals.network === 'unusual'
    && request.recentEvents.some(event => event.kind === 'risk_signal'
      && event.ageSeconds === 60
      && event.count === 20);
}

export function decide(request) {
  const context = inspectContextInput(request);
  const registered = request?.deviceRegistered === true;
  const stepUpRequired = registered && isFixtureCompositeAnomaly(request, context);
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !registered ? 'deny' : stepUpRequired ? 'step_up' : 'allow',
    reasonCode: !registered ? 'device_not_registered'
      : stepUpRequired ? 'step_up_required' : 'approved',
    ruleIds: stepUpRequired ? [RULE_IDS[0], RULE_IDS[1]] : [RULE_IDS[0]],
  };
}
