import { appendFile, readFile, rename, rm, writeFile } from 'node:fs/promises';
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

async function readLoggedAlertIds(logPath) {
  let contents;
  try {
    contents = await readFile(logPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return new Set();
    throw error;
  }

  const ids = new Set();
  for (const line of contents.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (typeof entry?.alertId === 'string') ids.add(entry.alertId);
    } catch {
      // Preserve older or malformed lines; they do not identify a logged alert.
    }
  }
  return ids;
}

async function replaceCandidateSnapshot(candidatePath, candidates) {
  const temporaryPath = `${candidatePath}.${process.pid}.tmp`;
  const document = {
    schema: 'aleph.xdr.deny-candidates.v1',
    rules: candidates,
  };

  try {
    await writeFile(temporaryPath, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
    await rename(temporaryPath, candidatePath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

export async function processFixture({ root, now = new Date() }) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'web-injection.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('web-injection 경보 묶음 형식이 아닙니다.');
  }

  const denyCandidates = [];
  const logLines = [];
  const counts = { block: 0, alert: 0, record: 0 };
  const loggedIds = await readLoggedAlertIds(join(root, 'xdr', 'alerts.log'));

  for (const alert of fixture.alerts) {
    const decision = await decide(alert);
    if (!Object.hasOwn(counts, decision?.action)) {
      throw new Error(`지원하지 않는 decide 결과: ${alert?.id ?? '(id 없음)'}`);
    }
    counts[decision.action] += 1;

    const candidate = createDenyCandidate(alert, decision, now);
    if (candidate) denyCandidates.push(candidate);

    if (decision.action !== 'record' && !loggedIds.has(alert.id)) {
      logLines.push(JSON.stringify({
        alertId: alert.id,
        action: decision.action,
        reason: decision.reason,
      }));
      loggedIds.add(alert.id);
    }
  }

  const candidatePath = join(root, 'xdr', 'web-injection', 'deny-rules.json');
  await replaceCandidateSnapshot(candidatePath, denyCandidates);

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
    process.stdout.write('후보 목록은 연습 자료이며 ZTNA 판정기에 자동 적용되지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
