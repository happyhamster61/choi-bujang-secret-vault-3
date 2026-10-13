import { appendFile, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULE_TTL_MS = 30 * 60 * 1000;

function redactSecretLikeText(value) {
  return String(value ?? '')
    .replace(/\b(password|passwd|pwd|token|access[_ -]?token|refresh[_ -]?token|secret|api[_ -]?key|private[_ -]?key|authorization|cookie|credential)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi, '$1$2[redacted]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[redacted private key]')
    .replace(/[\r\n]+/g, ' ');
}

export function createDenyCandidate(alert, decision, now = new Date()) {
  if (decision?.action !== 'block'
      || typeof decision.confidence !== 'number'
      || decision.confidence < 0.85) return null;

  const sourceAddress = alert?.data?.srcip;
  const alertId = alert?.id;
  if (typeof sourceAddress !== 'string' || !sourceAddress.trim()
      || typeof alertId !== 'string' || !alertId.trim()) return null;

  return {
    effect: 'deny',
    sourceAddress,
    alertId,
    expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
    reason: redactSecretLikeText(decision.reason),
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
      // Keep existing lines intact; malformed lines cannot identify an alert.
    }
  }
  return ids;
}

export async function processFixture({ root, now = new Date() }) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'known-cve.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('known-cve 경보 묶음 형식이 아닙니다.');
  }

  const denyCandidates = [];
  const logLines = [];
  const counts = { block: 0, alert: 0, record: 0 };
  const logPath = join(root, 'xdr', 'alerts.log');
  const loggedIds = await readLoggedAlertIds(logPath);

  for (const alert of fixture.alerts) {
    const result = await decide(alert);
    if (!Object.hasOwn(counts, result?.action)
        || typeof result.confidence !== 'number'
        || !Number.isFinite(result.confidence)
        || result.confidence < 0 || result.confidence > 1
        || typeof result.reason !== 'string') {
      throw new Error(`지원하지 않는 decide 결과: ${alert?.id ?? '(id 없음)'}`);
    }
    counts[result.action] += 1;

    const candidate = createDenyCandidate(alert, result, now);
    if (candidate) denyCandidates.push(candidate);

    if (typeof alert?.id !== 'string' || !alert.id.trim()) {
      throw new Error('경보에 기록할 id가 없습니다.');
    }
    if (!loggedIds.has(alert.id)) {
      logLines.push(JSON.stringify({
        alertId: alert.id,
        action: result.action,
        reason: redactSecretLikeText(result.reason),
      }));
      loggedIds.add(alert.id);
    }
  }

  if (logLines.length > 0) {
    await appendFile(logPath, `${logLines.join('\n')}\n`, 'utf8');
  }

  return { counts, denyCandidates, loggedAlerts: logLines.length };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const result = await processFixture({ root });
    process.stdout.write(`${JSON.stringify({ counts: result.counts, denyCandidates: result.denyCandidates, loggedAlerts: result.loggedAlerts })}\n`);
    process.stdout.write('차단 후보는 기존 형식의 메모리 결과이며 ZTNA 규칙에 자동 적용되지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
