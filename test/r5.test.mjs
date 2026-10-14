import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://choi-bujang-secret-vault-3-8kqo.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('5단계 build identity retains its stage number', () => {
  assert.equal(deploymentIdentity(env, { ...config, step: 5 }).step, 5);
});

test('5단계 자기 점검은 무로그인 notes API의 응답만 기록한다', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks({ ...config, step: 5 });
    assert.equal(requestUrl, 'https://student-defense.vercel.app/api/notes');
    assert.equal(options.method, 'GET');
    assert.equal(new Headers(options.headers).has('Authorization'), false);
    assert.equal(options.redirect, 'error');
    assert.equal(result.observed, 'HTTP 401 LOGIN_REQUIRED');
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks({ ...config, step: 5 });
    assert.equal(failed.observed, 'HTTP 200');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('6단계 제출 자기 점검도 무로그인 notes API의 실제 관찰 형식을 사용한다', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      assert.equal(init.method, 'GET');
      assert.equal(new Headers(init.headers).has('Authorization'), false);
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks({ ...config, step: 6 });
    assert.equal(requestUrl, 'https://student-defense.vercel.app/api/notes');
    assert.deepEqual(result, {
      attackId: 'notes_list_without_login',
      expected: 'HTTP 401 LOGIN_REQUIRED',
      observed: 'HTTP 401 LOGIN_REQUIRED',
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
