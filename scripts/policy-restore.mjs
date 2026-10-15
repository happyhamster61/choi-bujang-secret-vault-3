import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { previewPolicyRestore, restoreTestPolicy } from '../src/policy-restore.mjs';

const root = resolve(import.meta.dirname, '..');
const target = resolve(root, 'artifacts', 'stage10-test-policy.json');
const backup = JSON.parse(await readFile(resolve(root, 'backups', 'stage9-safe-policy.json')));
const candidate = JSON.parse(await readFile(target));
const plan = previewPolicyRestore(candidate, backup);
console.log(JSON.stringify(plan, null, 2));
if (process.argv.includes('--apply')) {
  const reviewed = process.argv.find(arg => arg.startsWith('--confirm-sha256='))?.split('=')[1];
  const restored = restoreTestPolicy(candidate, backup, reviewed);
  await mkdir(resolve(root, 'artifacts'), { recursive: true });
  await writeFile(target, JSON.stringify(restored, null, 2) + '\n',
    { encoding: 'utf8', flag: 'w' });
  console.log('시험 정책만 복원했습니다. 운영 정책과 감사 기록은 변경하지 않았습니다.');
} else {
  console.log('미리보기만 수행했습니다. 시험 정책에도 변경이 없습니다.');
}
