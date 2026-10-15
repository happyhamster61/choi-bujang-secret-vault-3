import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, inspectContextInput } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const responseKeys = ['schema', 'requestId', 'decision', 'reasonCode', 'ruleIds'];

function request(overrides = {}) {
  return {
    requestId: 'input-check-fixture',
    deviceRegistered: true,
    ...overrides,
  };
}

test('가상 신호 출처는 fixture로 분류하고 판정 응답은 기기 규칙을 유지한다', () => {
  const { normal } = fixtureRequests();

  assert.deepEqual(inspectContextInput(normal), {
    sourceClass: 'fixture',
    signalsShapeValid: true,
    recentEventsShapeValid: true,
  });
  const response = decide(normal);
  assert.equal(response.decision, 'allow');
  assert.deepEqual(Object.keys(response).sort(), [...responseKeys].sort());
});

test('fixture의 세 조건이 함께 있는 등록 기기 요청은 추가 확인으로 보낸다', () => {
  const { suspicious } = fixtureRequests();
  const response = decide(suspicious);

  assert.equal(response.decision, 'step_up');
  assert.equal(response.reasonCode, 'step_up_required');
  assert.deepEqual(response.ruleIds, ['device_registered', 'step_up_required']);
  assert.deepEqual(Object.keys(response).sort(), [...responseKeys].sort());
});

test('세 조건 중 하나라도 없는 요청은 추가 확인 규칙을 적용하지 않는다', () => {
  const { suspicious } = fixtureRequests();
  const cases = [
    { ...suspicious, signals: { ...suspicious.signals, hour: 14 } },
    { ...suspicious, signals: { ...suspicious.signals, network: 'usual' } },
    { ...suspicious, recentEvents: [] },
  ];

  for (const input of cases) {
    const response = decide(input);
    assert.equal(response.decision, 'allow');
    assert.equal(response.reasonCode, 'approved');
    assert.deepEqual(response.ruleIds, ['device_registered']);
  }
});

test('지역만 달라진 정상 fixture는 허용하고 step_up 규칙을 적용하지 않는다', () => {
  const { normal } = fixtureRequests();
  const input = { ...normal, signals: { ...normal.signals, region: 'foreign' } };
  const response = decide(input);

  assert.equal(response.decision, 'allow');
  assert.equal(response.reasonCode, 'approved');
  assert.deepEqual(response.ruleIds, ['device_registered']);
});

test('미등록 또는 등록 미확인 기기는 복합 사건이어도 기존 deny를 유지한다', () => {
  const { suspicious } = fixtureRequests();
  const responses = [
    decide({ ...suspicious, deviceRegistered: false }),
    decide({ ...suspicious, deviceRegistered: undefined }),
  ];

  for (const response of responses) {
    assert.equal(response.decision, 'deny');
    assert.equal(response.reasonCode, 'device_not_registered');
    assert.deepEqual(response.ruleIds, ['device_registered']);
  }
});

test('source none과 unknown 신호값을 정상 접속값으로 바꾸지 않는다', () => {
  const signals = { source: 'none', region: 'unknown', network: 'unknown', hour: null };
  const input = request({ signals, recentEvents: [] });

  assert.deepEqual(inspectContextInput(input), {
    sourceClass: 'none',
    signalsShapeValid: true,
    recentEventsShapeValid: true,
  });
  assert.deepEqual(input.signals, signals);
  assert.equal(decide(input).decision, 'allow');
});

test('signals와 recentEvents가 없으면 알 수 없음과 누락 상태를 유지한다', () => {
  const input = request();
  const before = structuredClone(input);

  assert.deepEqual(inspectContextInput(input), {
    sourceClass: 'unknown',
    signalsShapeValid: false,
    recentEventsShapeValid: false,
  });
  assert.deepEqual(input, before);
  assert.equal(Object.hasOwn(input, 'signals'), false);
  assert.equal(Object.hasOwn(input, 'recentEvents'), false);
  assert.equal(decide(input).decision, 'allow');
});

test('계약에 의미가 정의되지 않은 출처는 unknown으로 남긴다', () => {
  const input = request({
    signals: { source: 'unlisted_source', region: 'north', network: 'usual', hour: 14 },
    recentEvents: [{ kind: 'login', ageSeconds: 60, count: 1 }],
  });

  assert.deepEqual(inspectContextInput(input), {
    sourceClass: 'unknown',
    signalsShapeValid: true,
    recentEventsShapeValid: true,
  });
  assert.equal(decide(input).decision, 'allow');
});

test('위조된 클라이언트 헤더 모양의 값은 계약 입력으로 승격하지 않는다', () => {
  const input = request({
    headers: {
      'x-forwarded-for': '203.0.113.10',
      'x-region': 'north',
      'x-network': 'usual',
      'x-hour': '14',
      'x-recent-action': 'read',
    },
  });

  assert.deepEqual(inspectContextInput(input), {
    sourceClass: 'unknown',
    signalsShapeValid: false,
    recentEventsShapeValid: false,
  });
  assert.equal(decide(input).decision, 'allow');
  assert.deepEqual(Object.keys(decide(input)).sort(), [...responseKeys].sort());
});
