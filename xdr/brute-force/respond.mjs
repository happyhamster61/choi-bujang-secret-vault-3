import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULE_TTL_MS = 30 * 60 * 1000;

export function createDenyCandidate(alert, decision, now = new Date()) {
  if (decision?.action !== 'block' || decision.confidence < 0.85) return null;

  const sourceAddress = alert?.data?.srcip;
  const alertId = alert?.id;
  if (typeof sourceAddress !== 'string' || typeof alertId !== 'string') return null;

  return {
    effect: 'deny',
    sourceAddress,
    alertId,
    expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
    reason: decision.reason,
  };
}

export async function processFixture({ root, now = new Date() }) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'brute-force.json');
  const alerts = JSON.parse(await readFile(fixturePath, 'utf8')).alerts;
  const denyCandidates = [];
  const logLines = [];
  const counts = { block: 0, alert: 0, record: 0 };

  for (const alert of alerts) {
    const decision = await decide(alert);
    counts[decision.action] += 1;

    const candidate = createDenyCandidate(alert, decision, now);
    if (candidate) denyCandidates.push(candidate);

    if (decision.action !== 'record') {
      logLines.push(JSON.stringify({
        alertId: alert.id,
        action: decision.action,
        reason: decision.reason,
      }));
    }
  }

  const candidatePath = join(root, 'xdr', 'brute-force', 'deny-rules.json');
  await writeFile(candidatePath, `${JSON.stringify({ schema: 'aleph.xdr.deny-candidates.v1', rules: denyCandidates }, null, 2)}\n`, 'utf8');

  if (logLines.length > 0) {
    await appendFile(join(root, 'xdr', 'alerts.log'), `${logLines.join('\n')}\n`, 'utf8');
  }

  return { counts, denyCandidates, loggedAlerts: logLines.length };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const result = await processFixture({ root });
    process.stdout.write(`${JSON.stringify({ counts: result.counts, denyCandidates: result.denyCandidates.length, loggedAlerts: result.loggedAlerts })}\n`);
    process.stdout.write('deny-rules.json은 만료 시각이 있는 연습용 후보 목록이며 ZTNA 판정기에 자동 적용되지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
