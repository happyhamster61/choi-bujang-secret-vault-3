import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, inspectContextInput } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const responseKeys = ['schema', 'requestId', 'decision', 'reasonCode', 'ruleIds'];

function input({ hour = 14, network = 'usual', events = [], source = 'judge_fixture',
  region = 'local', deviceRegistered = true, extra = {} } = {}) {
  return {
    requestId: 'stage-7-local-test',
    deviceRegistered,
    stepUp: { verified: false, authAgeSeconds: null },
    signals: { source, region, network, hour },
    recentEvents: events,
    ...extra,
  };
}

function assertDecision(request, expected) {
  const response = decide(request);
  assert.equal(response.decision, expected);
  assert.deepEqual(Object.keys(response).sort(), [...responseKeys].sort());
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.schema, 'aleph.decision.v1');
  return response;
}

test('A. 정상 등록 기기는 allow하고 응답 계약을 유지한다', () => {
  const { normal } = fixtureRequests();
  assert.equal(decide(normal).decision, 'allow');
  assert.deepEqual(Object.keys(decide(normal)).sort(), [...responseKeys].sort());
});

test('B. 기존 공식 복합 fixture는 step_up이다', () => {
  const { suspicious } = fixtureRequests();
  const response = assertDecision(suspicious, 'step_up');
  assert.equal(response.reasonCode, 'step_up_required');
  assert.deepEqual(response.ruleIds, ['device_registered', 'step_up_required']);
});

test('C. 새벽 2시, first_seen, read 10회/30초는 step_up이다', () => {
  assertDecision(input({ hour: 2, network: 'first_seen',
    events: [{ kind: 'read', ageSeconds: 30, count: 10 }] }), 'step_up');
});

test('D. 새벽 5시, unusual, bulk_read 15회/120초는 step_up이다', () => {
  assertDecision(input({ hour: 5, network: 'unusual',
    events: [{ kind: 'bulk_read', ageSeconds: 120, count: 15 }] }), 'step_up');
});

test('E. 밤 22시, new, risk_signal 20회/60초는 가상 위험 대리 신호로 step_up이다', () => {
  assertDecision(input({ hour: 22, network: 'new',
    events: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] }), 'step_up');
});

test('F. 정상 시간 + 이상 네트워크 + 읽기 다량은 allow이다', () => {
  assertDecision(input({ hour: 14, network: 'unusual',
    events: [{ kind: 'read', ageSeconds: 30, count: 20 }] }), 'allow');
});

test('G. 비정상 시간 + 정상 네트워크 + 읽기 다량은 allow이다', () => {
  assertDecision(input({ hour: 2, network: 'known',
    events: [{ kind: 'read', ageSeconds: 30, count: 20 }] }), 'allow');
});

test('H. 비정상 시간 + 이상 네트워크 + 읽기 2회는 allow이다', () => {
  assertDecision(input({ hour: 2, network: 'unusual',
    events: [{ kind: 'read', ageSeconds: 30, count: 2 }] }), 'allow');
});

test('I. 지역만 급변한 정상 요청은 allow이며 지역은 판정 조건이 아니다', () => {
  assertDecision(input({ hour: 14, network: 'usual', region: 'foreign' }), 'allow');
});

test('J. 미등록 기기의 복합 이상 사건은 기존 deny를 유지한다', () => {
  const response = assertDecision(input({ hour: 2, network: 'new', deviceRegistered: false,
    events: [{ kind: 'read', ageSeconds: 30, count: 10 }] }), 'deny');
  assert.equal(response.reasonCode, 'device_not_registered');
  assert.deepEqual(response.ruleIds, ['device_registered']);
});

test('K. 읽기가 아닌 login 30회는 다량 읽기로 계산하지 않는다', () => {
  assertDecision(input({ hour: 2, network: 'unusual',
    events: [{ kind: 'login', ageSeconds: 30, count: 30 }] }), 'allow');
});

test('L. 누락·유효하지 않은 신호와 사건 값은 기본값으로 채우지 않고 step_up 조건에서 제외한다', () => {
  const base = input({ hour: 2, network: 'unusual',
    events: [{ kind: 'read', ageSeconds: 30, count: 10 }] });
  const cases = [
    { ...base, signals: { ...base.signals, hour: null } },
    { ...base, signals: { ...base.signals, hour: '2' } },
    { ...base, signals: { ...base.signals, hour: 24 } },
    { ...base, signals: { ...base.signals, hour: -1 } },
    { ...base, signals: { ...base.signals, hour: undefined } },
    { ...base, signals: { ...base.signals, network: 'unknown' } },
    { ...base, signals: { ...base.signals, network: null } },
    { ...base, signals: { ...base.signals, network: '' } },
    { ...base, signals: { ...base.signals, network: undefined } },
    { ...base, recentEvents: undefined },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: -1, count: 10 }] },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: 301, count: 10 }] },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: 30, count: -1 }] },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: 30, count: 2.5 }] },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: 30, count: Number.NaN }] },
    { ...base, recentEvents: [{ kind: 'read', ageSeconds: Number.NaN, count: 10 }] },
    { ...base, recentEvents: Array.from({ length: 13 }, () =>
      ({ kind: 'read', ageSeconds: 30, count: 1 })) },
  ];
  for (const request of cases) assertDecision(request, 'allow');
});

test('M. 임의 클라이언트 헤더는 계약 신호가 아니므로 판정에 영향이 없다', () => {
  const { normal } = fixtureRequests();
  const forged = { ...normal, headers: {
    'x-forwarded-for': '203.0.113.10', 'x-region': 'foreign', 'x-network': 'new',
    'x-hour': '2', 'x-recent-action': 'read',
  } };
  assert.equal(inspectContextInput(forged).signalsShapeValid, true);
  assertDecision(forged, 'allow');

  const headerOnly = {
    requestId: 'header-only-test',
    deviceRegistered: true,
    headers: forged.headers,
  };
  assert.deepEqual(inspectContextInput(headerOnly), {
    sourceClass: 'unknown', signalsShapeValid: false, recentEventsShapeValid: false,
  });
  assertDecision(headerOnly, 'allow');
});

test('N. 5분 창 안의 여러 읽기 사건 count 합이 8이면 step_up이다', () => {
  assertDecision(input({ hour: 2, network: 'first_seen', events: [
    { kind: 'read', ageSeconds: 30, count: 3 },
    { kind: 'file_read', ageSeconds: 300, count: 5 },
  ] }), 'step_up');
});

test('O. source none 및 unknown 위치·네트워크 값은 가상 위치 증거를 만들지 않는다', () => {
  const request = input({ source: 'none', hour: 2, region: 'unknown', network: 'new',
    events: [{ kind: 'read', ageSeconds: 30, count: 10 }] });
  assert.deepEqual(inspectContextInput(request), {
    sourceClass: 'none', signalsShapeValid: true, recentEventsShapeValid: true,
  });
  assert.equal(request.signals.region, 'unknown');
  assert.equal(request.signals.network, 'new');
  assertDecision(request, 'allow');
});

test('읽기 관련 kind 네 종류와 risk_signal만 행동 횟수에 포함한다', () => {
  for (const kind of ['read', 'bulk_read', 'file_read', 'notes_read', 'risk_signal']) {
    assertDecision(input({ hour: 2, network: 'unusual',
      events: [{ kind, ageSeconds: 30, count: 8 }] }), 'step_up');
  }
  for (const kind of ['login', 'logout', 'write', 'update', 'delete']) {
    assertDecision(input({ hour: 2, network: 'unusual',
      events: [{ kind, ageSeconds: 30, count: 30 }] }), 'allow');
  }
});

test('시간대 경계와 허용된 네트워크 분류를 적용한다', () => {
  for (const hour of [0, 7, 21, 23]) {
    assertDecision(input({ hour, network: 'new',
      events: [{ kind: 'read', ageSeconds: 30, count: 8 }] }), 'step_up');
  }
  for (const hour of [8, 14, 20]) {
    assertDecision(input({ hour, network: 'new',
      events: [{ kind: 'read', ageSeconds: 30, count: 8 }] }), 'allow');
  }
  for (const network of ['usual', 'known', 'familiar', 'trusted']) {
    assertDecision(input({ hour: 2, network,
      events: [{ kind: 'read', ageSeconds: 30, count: 8 }] }), 'allow');
  }
  for (const network of ['unusual', 'first_seen', 'new', 'unknown_network']) {
    assertDecision(input({ hour: 2, network,
      events: [{ kind: 'read', ageSeconds: 30, count: 8 }] }), 'step_up');
  }
});

test('출처 누락·불명확은 unknown으로 유지하고 출처만으로 이상 조건을 만들지 않는다', () => {
  const noSource = input({ source: undefined });
  delete noSource.signals.source;
  assert.equal(inspectContextInput(noSource).sourceClass, 'unknown');
  assertDecision(noSource, 'allow');

  const unknownSource = input({ source: 'unlisted_source' });
  assert.equal(inspectContextInput(unknownSource).sourceClass, 'unknown');
  assertDecision(unknownSource, 'allow');

  const noContext = { requestId: 'missing-context-test', deviceRegistered: true };
  const before = structuredClone(noContext);
  assert.deepEqual(inspectContextInput(noContext), {
    sourceClass: 'unknown', signalsShapeValid: false, recentEventsShapeValid: false,
  });
  assertDecision(noContext, 'allow');
  assert.deepEqual(noContext, before);
});

test('미확인 출처의 복합 입력도 출처 자체가 아니라 세 신호가 충족될 때만 step_up이다', () => {
  const request = input({ source: 'unlisted_source', hour: 2, network: 'first_seen',
    events: [{ kind: 'notes_read', ageSeconds: 30, count: 8 }] });
  assert.equal(inspectContextInput(request).sourceClass, 'unknown');
  assertDecision(request, 'step_up');
});

test('stepUp.verified만으로 복합 이상 요청을 allow로 바꾸지 않는다', () => {
  const { suspicious } = fixtureRequests();
  assertDecision({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, 'step_up');
});
