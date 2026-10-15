import assert from 'node:assert/strict';
import { test } from 'node:test';
import restore from '../api/restore.js';

function makeResponse() {
  const result = { headers: {}, status: null, body: null };
  const response = {
    setHeader(key, value) { result.headers[key] = value; return this; },
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
  };
  return { response, result };
}
test('복구 API는 POST만 허용하고 무로그인 요청을 거부한다', async () => {
  const { response, result } = makeResponse();
  await restore({ method: 'GET', headers: {} }, response);
  assert.equal(result.status, 405);
  assert.deepEqual(result.body, { error: 'METHOD_NOT_ALLOWED' });
  assert.equal(result.headers['Cache-Control'], 'no-store');
  const other = makeResponse();
  await restore({ method: 'POST', headers: {}, body: { id: 'not-a-real-id' } },
    other.response);
  assert.equal(other.result.status, 401);
  assert.deepEqual(other.result.body, { error: 'LOGIN_REQUIRED' });
});
test('API는 기존 사용자·정책을 변경하는 작업을 제공하지 않는다', async () => {
  const { response, result } = makeResponse();
  await restore({ method: 'PUT', headers: {},
    body: { role: 'instructor', owner_id: 'forged' } }, response);
  assert.equal(result.status, 405);
});
