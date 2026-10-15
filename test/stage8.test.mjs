import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';

const base = Object.freeze({
  schema: 'aleph.decision.v1', requestId: 'stage8-virtual',
  deviceRegistered: true, service: 'notes', method: 'GET',
  route: 'GET /api/notes/:id', path: '/api/notes/virtual-id',
  signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
  recentEvents: [], stepUp: { verified: false, authAgeSeconds: null },
});
function check(change, expected) {
  const request = { ...base, ...change };
  const result = decide(request);
  assert.deepEqual(Object.keys(result).sort(),
    ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(result.schema, 'aleph.decision.v1');
  assert.equal(result.requestId, request.requestId);
  assert.equal(result.decision, expected);
  assert.ok(result.ruleIds.length > 0);
  for (const id of result.ruleIds) assert.ok(RULE_IDS.includes(id));
}
test('8단계 가상 메모 단건 읽기·수정·삭제는 허용된다', () => {
  for (const method of ['GET', 'PUT', 'DELETE']) {
    check({ method, route: `${method} /api/notes/:id` }, 'allow');
  }
});
test('8단계 자원 ID 형식은 UUID로 제한하지 않는다', () => {
  check({ path: '/api/notes/stage8-virtual-id' }, 'allow');
});
test('8단계 메모 목록·생성·기능·알 수 없는 경로는 거부한다', () => {
  check({ route: 'GET /api/notes', path: '/api/notes' }, 'deny');
  check({ method: 'POST', route: 'POST /api/notes', path: '/api/notes' }, 'deny');
  check({ path: '/api/notes/export' }, 'deny');
  check({ path: '/api/notes/test/extra' }, 'deny');
  check({ service: 'unknown' }, 'deny');
  check({ route: 'GET /api/notes/:id', path: '/api/other/test' }, 'deny');
});
test('반 공지는 읽기만 허용하며 임의 쓰기는 거부한다', () => {
  check({ service: 'class_announcements', route: 'GET /api/class-announcements/:id',
    path: '/api/class-announcements/class-note' }, 'allow');
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    check({ service: 'class_announcements', method,
      route: `${method} /api/class-announcements/:id`,
      path: '/api/class-announcements/class-note' }, 'deny');
  }
});
test('강사 자료와 미등록 기기는 항상 거부한다', () => {
  check({ service: 'instructor_materials', route: 'GET /api/instructor-materials/:id',
    path: '/api/instructor-materials/staff-record' }, 'deny');
  check({ deviceRegistered: false }, 'deny');
});
test('복합 이상 감지와 엔진 재확인 5분 규칙은 유지한다', () => {
  const suspicious = { signals: { source: 'judge_fixture', region: 'foreign',
    network: 'unusual', hour: 3 },
  recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] };
  check(suspicious, 'step_up');
  check({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 300 } }, 'allow');
  check({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 301 } }, 'step_up');
});
