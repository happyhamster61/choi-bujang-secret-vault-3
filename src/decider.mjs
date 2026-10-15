// ALEPH SDP 엔진이 확인한 요청만 받습니다. 등록 상태는 엔진이 확인한 계약 필드입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

const SIGNAL_FIELDS = ['source', 'region', 'network', 'hour'];
const EVENT_FIELDS = ['kind', 'ageSeconds', 'count'];

// Explicit local stage-7 policy; the decision contract defines no baseline or thresholds.
const LOCAL_POLICY = Object.freeze({
  unusualHourStart: 21,
  unusualHourEnd: 7,
  recentEventWindowSeconds: 300,
  minimumReadCount: 8,
});
const UNUSUAL_NETWORKS = new Set(['unusual', 'first_seen', 'new', 'unknown_network']);
const USUAL_NETWORKS = new Set(['usual', 'known', 'familiar', 'trusted']);
const READ_EVENT_KINDS = new Set(['read', 'bulk_read', 'file_read', 'notes_read', 'risk_signal']);

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

function hasAtypicalHour(signals) {
  const { hour } = signals;
  if (!Number.isInteger(hour) || hour < 0 || hour > 23) return false;
  return hour >= LOCAL_POLICY.unusualHourStart || hour <= LOCAL_POLICY.unusualHourEnd;
}

function classifyNetwork(network) {
  if (typeof network !== 'string' || network.length === 0 || network === 'unknown') {
    return 'insufficient';
  }
  if (UNUSUAL_NETWORKS.has(network)) return 'unusual';
  if (USUAL_NETWORKS.has(network)) return 'usual';
  return 'insufficient';
}

function hasUnfamiliarNetwork(signals) {
  return classifyNetwork(signals.network) === 'unusual';
}

function hasRecentHighVolumeEvent(events) {
  let readCount = 0;
  for (const event of events) {
    if (!READ_EVENT_KINDS.has(event.kind)
        || !Number.isFinite(event.ageSeconds)
        || event.ageSeconds < 0
        || event.ageSeconds > LOCAL_POLICY.recentEventWindowSeconds
        || !Number.isInteger(event.count)
        || event.count < 0) {
      continue;
    }
    readCount += event.count;
    if (readCount >= LOCAL_POLICY.minimumReadCount) return true;
  }
  return false;
}

function hasCompositeAnomaly(request, context) {
  // `none` means the actual request path has no verified context; fixture-like values are not evidence.
  // Unknown source alone contributes no signal. Missing values are never synthesized.
  return context.signalsShapeValid
    && context.recentEventsShapeValid
    && context.sourceClass !== 'none'
    && hasAtypicalHour(request.signals)
    && hasUnfamiliarNetwork(request.signals)
    && hasRecentHighVolumeEvent(request.recentEvents);
}

export function decide(request) {
  const context = inspectContextInput(request);
  const registered = request?.deviceRegistered === true;
  const stepUpRequired = registered && hasCompositeAnomaly(request, context);
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !registered ? 'deny' : stepUpRequired ? 'step_up' : 'allow',
    reasonCode: !registered ? 'device_not_registered'
      : stepUpRequired ? 'step_up_required' : 'approved',
    ruleIds: stepUpRequired ? [RULE_IDS[0], RULE_IDS[1]] : [RULE_IDS[0]],
  };
}
