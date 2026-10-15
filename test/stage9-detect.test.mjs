import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';

const BASE = Date.UTC(2026, 9, 1);
function reads(count, { start = BASE, gapMs = 1000, sub = 'fixture_sub', method = 'GET' } = {}) {
  return Array.from({ length: count }, (_, n) => ({
    at: new Date(start + n * gapMs).toISOString(),
    method, identity: { sub },
  }));
}
const observe = { action: 'observe' };
const revoke = sub => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject: sub });

test('정상 120회는 유지하고 121회부터 가명 사용자 회수를 제안한다', () => {
  assert.deepEqual(detect(reads(120)), observe);
  assert.deepEqual(detect(reads(121)), revoke('fixture_sub'));
});
test('같은 사용자의 정확히 10분 경계는 포함하고 초과는 제외한다', () => {
  assert.deepEqual(detect(reads(121, { gapMs: 5000 })), revoke('fixture_sub'));
  assert.deepEqual(detect(reads(121, { gapMs: 5001 })), observe);
});
test('다른 사용자 조회는 서로 합산하지 않는다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { sub: 'other_fixture' })]), observe);
  assert.deepEqual(detect([...reads(121, { sub: 'other_fixture' }), ...reads(5)]),
    revoke('other_fixture'));
});
test('GET 이외 메서드를 폭주 조회에 포함하지 않는다', () => {
  assert.deepEqual(detect([...reads(120), ...reads(100, { method: 'POST' })]), observe);
});
test('정렬되지 않은 사건의 어느 10분 창에서도 탐지한다', () => {
  assert.deepEqual(detect([
    ...reads(30, { start: BASE - 900000, gapMs: 30000 }),
    ...reads(121, { start: BASE + 300000 }),
  ].reverse()), revoke('fixture_sub'));
});
test('세 계약값 없는 사건과 임의 기기·지역 입력은 신뢰하지 않는다', () => {
  assert.deepEqual(detect([null, {}, { at: 'invalid', method: 'GET', identity: { sub: 'x' } },
    { at: new Date(BASE).toISOString(), method: 'GET', identity: {} }]), observe);
  const withExtra = reads(121).map(event => ({ ...event,
    device: { registered: false }, region: 'fictional', token: 'not_a_real_token' }));
  assert.deepEqual(detect(withExtra), revoke('fixture_sub'));
});
test('탐지는 권한 회수나 기기 변경 없이 정확한 응답 키만 반환한다', () => {
  assert.deepEqual(Object.keys(detect(reads(121))).sort(),
    ['action', 'reasonCode', 'subject']);
  assert.deepEqual(Object.keys(detect(reads(30))), ['action']);
  assert.throws(() => detect(null), { name: 'TypeError' });
});
