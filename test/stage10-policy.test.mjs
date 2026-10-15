import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { previewPolicyRestore, restoreTestPolicy, verifySafePolicy,
  SAFE_POLICY_SHA256 } from '../src/policy-restore.mjs';
const backup = JSON.parse(readFileSync(new URL('../backups/stage9-safe-policy.json', import.meta.url)));
test('검증된 9단계 안전 사본 SHA256을 확인한다', () => {
  assert.equal(verifySafePolicy(backup), SAFE_POLICY_SHA256);
  assert.throws(() => verifySafePolicy({ ...backup, policyRules: [] }), /unverified/);
  assert.throws(() => verifySafePolicy(null), /unverified/);
});
test('시험 정책은 적용 전에 차이와 기준 커밋을 확인할 수 있다', () => {
  const changed = { allowedRoutes: ['GET /api/notes'], policyRules: [],
    unrelatedService: { keep: true }, auditHistory: ['retain'] };
  const plan = previewPolicyRestore(changed, backup);
  assert.deepEqual(plan.changes.map(x => x.field), ['allowedRoutes', 'policyRules']);
  assert.equal(plan.baselineCommit, backup.sourceCommit);
  assert.deepEqual(changed.allowedRoutes, ['GET /api/notes']);
  assert.throws(() => restoreTestPolicy(changed, backup, 'not-reviewed'),
    /restore_review_required/);
  const restored = restoreTestPolicy(changed, backup, plan.safeHash);
  assert.deepEqual(restored.allowedRoutes, backup.allowedRoutes);
  assert.deepEqual(restored.policyRules, backup.policyRules);
  assert.deepEqual(restored.unrelatedService, changed.unrelatedService);
  assert.deepEqual(restored.auditHistory, changed.auditHistory);
});
