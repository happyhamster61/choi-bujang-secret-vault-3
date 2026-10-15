// ALEPH SDP 엔진이 확인한 요청만 받습니다. 등록 상태는 엔진이 확인한 계약 필드입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone_allowed', 'resource_zone_denied']);

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

// Only an engine-verified, recent step-up may release an anomalous request.
// The device registration decision remains independent and takes precedence.
function hasFreshVerifiedStepUp(request) {
  const stepUp = request?.stepUp;
  return isRecord(stepUp)
    && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0
    && stepUp.authAgeSeconds <= 300;
}

// Stage 8: only verified engine service, method, route and exact path are used.
// Query parameters and claims supplied by browsers never select a zone.
const RESERVED_NOTE_SEGMENTS = new Set(['export', 'import', 'search', 'all', 'bulk']);
const NOTE_ROUTES = new Set(['/notes/:id', '/api/notes/:id']);
const CLASS_ROUTES = new Set(['/class-announcements/:id', '/api/class-announcements/:id',
  '/announcements/:id', '/api/announcements/:id']);
const INSTRUCTOR_ROUTES = new Set(['/instructor-materials/:id', '/api/instructor-materials/:id']);
const NOTE_SERVICES = new Set(['notes', 'note']);
const CLASS_SERVICES = new Set(['class_announcements', 'class-announcements',
  'announcements', 'class_notice']);
const INSTRUCTOR_SERVICES = new Set(['instructor_materials', 'instructor-materials',
  'instructor']);

function matchesItemPath(route, path, prefixes, reserved = new Set()) {
  if (typeof path !== 'string' || typeof route !== 'string'
      || path.includes('?') || path.includes('#') || path.includes('%')
      || path.includes('\\') || path.includes('//')) return false;
  for (const prefix of prefixes) {
    if (route !== prefix + '/:id' || !path.startsWith(prefix + '/')) continue;
    const id = path.slice(prefix.length + 1);
    // Accept virtual non-UUID IDs; prohibit route-depth function collisions.
    if (id.length > 0 && id.length <= 256 && !id.includes('/')
        && id !== '.' && id !== '..' && !reserved.has(id.toLowerCase())) return true;
  }
  return false;
}

function permittedResourceZone(request) {
  const method = request?.method;
  const service = request?.service;
  const routeText = request?.route;
  const path = request?.path;
  if (typeof routeText !== 'string' || typeof method !== 'string'
      || !routeText.startsWith(method + ' ')) return false;
  const route = routeText.slice(method.length + 1);
  if (NOTE_SERVICES.has(service) && ['GET', 'PUT', 'DELETE'].includes(method)
      && NOTE_ROUTES.has(route)) {
    return matchesItemPath(route, path, ['/notes', '/api/notes'], RESERVED_NOTE_SEGMENTS);
  }
  if (CLASS_SERVICES.has(service) && method === 'GET'
      && CLASS_ROUTES.has(route)) {
    return matchesItemPath(route, path,
      ['/class-announcements', '/api/class-announcements',
        '/announcements', '/api/announcements']);
  }
  // Instructor materials are never available through the student policy.
  return false;
}

export function decide(request) {
  const context = inspectContextInput(request);
  const registered = request?.deviceRegistered === true;
  const zoneAllowed = permittedResourceZone(request);
  const stepUpRequired = registered && zoneAllowed && hasCompositeAnomaly(request, context)
    && !hasFreshVerifiedStepUp(request);
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: !registered ? 'deny' : !zoneAllowed ? 'deny'
      : stepUpRequired ? 'step_up' : 'allow',
    reasonCode: !registered ? 'device_not_registered'
      : !zoneAllowed ? 'access_denied'
      : stepUpRequired ? 'step_up_required' : 'approved',
    ruleIds: !registered ? [RULE_IDS[0]]
      : !zoneAllowed ? [RULE_IDS[0], RULE_IDS[3]]
        : stepUpRequired ? [RULE_IDS[0], RULE_IDS[2], RULE_IDS[1]]
          : [RULE_IDS[0], RULE_IDS[2]],
  };
}
