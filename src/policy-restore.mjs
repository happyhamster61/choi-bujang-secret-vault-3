import { createHash } from 'node:crypto';

export const SAFE_POLICY_SHA256 = '93e7db2e27ce5b19fc7f4125b2a0d65e0e4d3b080265814c156f229db253c6ab';
export const SAFE_POLICY_COMMIT = 'cbdbbed3bb5f2c97bb5efeb82c0d9e7ef750c27c';
const KEYS = ['allowedRoutes', 'policyRules'];

export function verifySafePolicy(backup) {
  if (!backup || typeof backup !== 'object' || Array.isArray(backup)
      || Object.keys(backup).sort().join(',') !==
        'allowedRoutes,policyRules,sourceCommit,version'
      || backup.version !== 9 || backup.sourceCommit !== SAFE_POLICY_COMMIT
      || !KEYS.every(k => Array.isArray(backup[k])
        && backup[k].every(x => typeof x === 'string'))) {
    throw new Error('unverified_safe_policy');
  }
  const hash = createHash('sha256').update(JSON.stringify(backup)).digest('hex');
  if (hash !== SAFE_POLICY_SHA256) throw new Error('unverified_safe_policy');
  return hash;
}

export function previewPolicyRestore(candidate, backup) {
  const sourceHash = verifySafePolicy(backup);
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('invalid_test_policy');
  }
  const changes = [];
  for (const key of KEYS) {
    const before = candidate[key];
    const after = backup[key];
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({ field: key, current: before ?? null, restoreTo: [...after] });
    }
  }
  return { baselineVersion: backup.version, baselineCommit: backup.sourceCommit,
    safeHash: sourceHash, changes };
}

export function restoreTestPolicy(candidate, backup, reviewedHash) {
  const preview = previewPolicyRestore(candidate, backup);
  if (reviewedHash !== preview.safeHash) throw new Error('restore_review_required');
  return { ...candidate,
    allowedRoutes: [...backup.allowedRoutes],
    policyRules: [...backup.policyRules],
  };
}
