import { readFile, writeFile } from 'node:fs/promises';
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

async function readLogContents(logPath) {
  try {
    return await readFile(logPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return '';
    throw error;
  }
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
  const counts = { block: 0, alert: 0, record: 0 };
  const logPath = join(root, 'xdr', 'alerts.log');
  const previousLog = await readLogContents(logPath);
  const fixtureIds = new Set();
  const expectedLines = new Map();

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
    fixtureIds.add(alert.id);
    expectedLines.set(alert.id, JSON.stringify({
      alertId: alert.id,
      action: result.action,
      reason: redactSecretLikeText(result.reason),
    }));
  }

  const hadTrailingNewline = /(?:\r?\n)$/.test(previousLog);
  const newline = previousLog.includes('\r\n') ? '\r\n' : '\n';
  const previousLines = previousLog.split(/\r?\n/u);
  if (hadTrailingNewline) previousLines.pop();
  const seen = new Set();
  const nextLines = [];
  let updatedAlerts = 0;
  for (const line of previousLines) {
    let alertId;
    try { alertId = JSON.parse(line)?.alertId; } catch { /* Preserve unrelated or malformed lines. */ }
    if (typeof alertId !== 'string' || !fixtureIds.has(alertId)) {
      nextLines.push(line);
      continue;
    }
    if (seen.has(alertId)) continue;
    seen.add(alertId);
    const expected = expectedLines.get(alertId);
    nextLines.push(expected);
    if (line !== expected) updatedAlerts += 1;
  }
  let loggedAlerts = 0;
  for (const alert of fixture.alerts) {
    if (seen.has(alert.id)) continue;
    nextLines.push(expectedLines.get(alert.id));
    seen.add(alert.id);
    loggedAlerts += 1;
  }
  const nextLog = nextLines.length ? `${nextLines.join(newline)}${newline}` : '';
  if (nextLog !== previousLog) await writeFile(logPath, nextLog, 'utf8');

  return { counts, denyCandidates, loggedAlerts, updatedAlerts };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const result = await processFixture({ root });
    process.stdout.write(`${JSON.stringify({ counts: result.counts, denyCandidates: result.denyCandidates, loggedAlerts: result.loggedAlerts, updatedAlerts: result.updatedAlerts })}\n`);
    process.stdout.write('차단 후보는 기존 형식의 메모리 결과이며 ZTNA 규칙에 자동 적용되지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
