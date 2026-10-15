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
// The contract does not enumerate the strings below. These aliases interpret
// explicit engine-provided *virtual* indicators; unknown values remain insufficient.
const UNUSUAL_NETWORKS = new Set([
  'unusual', 'first_seen', 'first_time', 'first_seen_network', 'new',
  'new_network', 'unknown_network', 'unfamiliar', 'unrecognized', 'untrusted',
]);
const USUAL_NETWORKS = new Set(['usual', 'known', 'familiar', 'trusted']);
const READ_EVENT_KINDS = new Set([
  'read', 'bulk_read', 'file_read', 'notes_read', 'note_read',
  'read_file', 'read_note', 'file_access', 'notes_access',
  'mass_read', 'bulk_file_read', 'risk_signal',
]);

function normalizeIndicator(value) {
  if (typeof value !== 'string' || value.length > 80) return null;
  const normalized = value.trim().toLowerCase().replace(/[\s-]+/gu, '_');
  return /^[a-z][a-z0-9_]*$/u.test(normalized) ? normalized : null;
}

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
  const value = normalizeIndicator(network);
  if (value === null || value === 'unknown') return 'insufficient';
  if (UNUSUAL_NETWORKS.has(value)) return 'unusual';
  if (USUAL_NETWORKS.has(value)) return 'usual';
  return 'insufficient';
}

function hasUnfamiliarNetwork(signals) {
  return classifyNetwork(signals.network) === 'unusual';
}

function hasRecentHighVolumeEvent(events) {
  let readCount = 0;
  for (const event of events) {
    if (!READ_EVENT_KINDS.has(normalizeIndicator(event.kind))
        || !Number.isFinite(event.ageSeconds)
        || event.ageSeconds < 0
        || event.ageSeconds > LOCAL_POLICY.recentEventWindowSeconds
        || !Number.isInteger(event.count)
        || event.count < 0) {
      continue;
    }
    if (event.count >= LOCAL_POLICY.minimumReadCount - readCount) return true;
    readCount += event.count;
  }
  return false;
}

function hasCompositeAnomaly(request, context) {
  // Treat source as provenance metadata, not a fourth anomaly requirement.
  // Incomplete hour/network/events still cannot establish the three-factor anomaly.
  // No browser headers or region-only hints are promoted into signals.
  return context.signalsShapeValid
    && context.recentEventsShapeValid
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
