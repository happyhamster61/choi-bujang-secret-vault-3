import assert from 'node:assert/strict';
import { test } from 'node:test';
import notesItem from '../api/notes/[id].js';
import noticesItem from '../api/class-announcements/[id].js';
import adminNotice from '../api/admin/class-announcements/[id].js';
import instructorItem from '../api/instructor-materials/[id].js';

const ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
function response() {
  const headers = {};
  const result = { headers, statusCode: null, body: null };
  const res = {
    setHeader(key, value) { headers[key.toLowerCase()] = value; return this; },
    status(code) { result.statusCode = code; return this; },
    json(value) { result.body = value; return this; },
    end() { return this; },
  };
  return { res, result };
}
async function call(handler, method, path, options = {}) {
  const { res, result } = response();
  await handler({
    method,
    url: path,
    headers: {},
    query: { id: path.split('/').at(-1) },
    ...options,
  }, res);
  assert.equal(result.headers['cache-control'], 'no-store');
  return result;
}

test('메모 단건은 로그인하지 않으면 직접 API도 거부한다', async () => {
  const res = await call(notesItem, 'GET', '/api/notes/' + ID);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'LOGIN_REQUIRED');
});
test('다른 ID를 query로 교체하려는 요청은 DB 접근 전에 거부한다', async () => {
  const res = await call(notesItem, 'GET', '/api/notes/' + ID,
    { query: { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' } });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'INVALID_NOTE_ID');
});
test('반 공지 수정은 학생 API에서 누구에게나 거부한다', async () => {
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const res = await call(noticesItem, method, '/api/class-announcements/' + ID);
    assert.equal(res.statusCode, 405);
    assert.equal(res.body.error, 'METHOD_NOT_ALLOWED');
  }
});
test('반 공지는 로그인 검증 없이는 API에서 공개되지 않는다', async () => {
  const res = await call(noticesItem, 'GET', '/api/class-announcements/' + ID);
  assert.equal(res.statusCode, 401);
});
test('강사 관리자 경로도 인증 없는 수정은 거부한다', async () => {
  const res = await call(adminNotice, 'PUT', '/api/admin/class-announcements/' + ID);
  assert.equal(res.statusCode, 401);
});
test('강사 자료 API는 무로그인 요청을 거부한다', async () => {
  const res = await call(instructorItem, 'GET', '/api/instructor-materials/' + ID);
  assert.equal(res.statusCode, 401);
});
