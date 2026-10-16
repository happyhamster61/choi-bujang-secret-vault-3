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

test('제출 자기 점검은 실제 심판 증거 없이 HTTP 결과를 만들거나 대체 요청을 보내지 않는다', async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0;
  try {
    globalThis.fetch = async () => {
      requests++;
      throw new Error('An unrecorded check must not send a substitute request');
    };
    for (let step = 3; step <= 12; step++) {
      assert.deepEqual(await runAttackChecks({ ...config, step }), [{
        attackId: 'notes_list_without_login',
        expected: 'HTTP 401 LOGIN_REQUIRED',
        observed: 'not_run',
      }]);
    }
    assert.equal(requests, 0);
    await assert.rejects(runAttackChecks({ ...config, step: 2 }));
    for (const publicAppUrl of ['http://student-defense.vercel.app',
      'https://student-defense.vercel.app/?token=test',
      'https://example.com', 'https://student-defense.vercel.app/api/notes']) {
      await assert.rejects(runAttackChecks({ ...config, step: 12, publicAppUrl }));
    }
    assert.equal(requests, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
