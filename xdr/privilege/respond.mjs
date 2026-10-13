import { appendFile, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULE_TTL_MS = 30 * 60 * 1000;
const DENY_CANDIDATE_SCHEMA = 'aleph.xdr.deny-candidates.v1';
const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|token|access[_ -]?token|refresh[_ -]?token|secret(?:[_ -]?key)?|api[_ -]?key|private[_ -]?key|access[_ -]?key|authorization|cookie|credential)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi;

export function redactSecretLikeText(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[redacted private key]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(/\bBasic\s+[A-Za-z0-9+/]+=*/gi, 'Basic [redacted]')
    .replace(SECRET_ASSIGNMENT, '$1$2[redacted]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted key]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/[\r\n]+/g, ' ');
}

export function createDenyCandidate(alert, decision, now = new Date()) {
  if (decision?.action !== 'block'
      || typeof decision.confidence !== 'number'
      || !Number.isFinite(decision.confidence)
      || decision.confidence < 0.85) return null;

  const sourceAddress = alert?.data?.srcip;
  const alertId = alert?.id;
  if (typeof sourceAddress !== 'string' || !sourceAddress.trim()
      || typeof alertId !== 'string' || !alertId.trim()
      || !(now instanceof Date) || !Number.isFinite(now.getTime())) return null;

  const safeSourceAddress = redactSecretLikeText(sourceAddress);
  if (safeSourceAddress.includes('[redacted')) return null;

  return {
    effect: 'deny',
    sourceAddress: safeSourceAddress,
    alertId: redactSecretLikeText(alertId),
    expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
    reason: redactSecretLikeText(decision.reason),
  };
}

export function processAlerts(alerts, now = new Date()) {
  if (!Array.isArray(alerts)) throw new TypeError('alerts 배열이 필요합니다.');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('now는 유효한 Date여야 합니다.');
  }

  const counts = { block: 0, alert: 0, record: 0 };
  const denyCandidates = [];
  const decisions = [];
  const logLines = [];
  const seenIds = new Set();

  for (const [index, alert] of alerts.entries()) {
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)
        || typeof alert.id !== 'string' || !alert.id.trim()) {
      throw new TypeError(`경보 ${index + 1}건에 유효한 id가 없습니다.`);
    }
    if (seenIds.has(alert.id)) throw new Error(`중복 경보 ID: ${alert.id}`);
    seenIds.add(alert.id);

    const decision = decide(alert);
    if (!Object.hasOwn(counts, decision?.action)
        || typeof decision.confidence !== 'number'
        || !Number.isFinite(decision.confidence)
        || decision.confidence < 0 || decision.confidence > 1
        || typeof decision.reason !== 'string') {
      throw new Error(`지원하지 않는 decide 결과: ${alert.id}`);
    }

    counts[decision.action] += 1;
    decisions.push({ alertId: redactSecretLikeText(alert.id), ...decision,
      reason: redactSecretLikeText(decision.reason) });

    const candidate = createDenyCandidate(alert, decision, now);
    if (candidate) denyCandidates.push(candidate);

    logLines.push(JSON.stringify({
      alertId: redactSecretLikeText(alert.id),
      action: decision.action,
      confidence: decision.confidence,
      reason: redactSecretLikeText(decision.reason),
    }));
  }

  return {
    schema: DENY_CANDIDATE_SCHEMA,
    counts,
    denyCandidates,
    decisions,
    logLines,
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

export function selectUnloggedLines(existingContents, logLines) {
  const seenIds = new Set();
  for (const line of existingContents.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (typeof entry?.alertId === 'string') seenIds.add(entry.alertId);
    } catch {
      // Preserve legacy or malformed lines; they cannot identify an alert.
    }
  }

  const pending = [];
  for (const line of logLines) {
    let alertId;
    try {
      alertId = JSON.parse(line)?.alertId;
    } catch {
      throw new TypeError('생성된 로그 행이 JSON 형식이 아닙니다.');
    }
    if (typeof alertId !== 'string' || !alertId.trim()) {
      throw new TypeError('생성된 로그 행에 alertId가 없습니다.');
    }
    if (seenIds.has(alertId)) continue;
    seenIds.add(alertId);
    pending.push(line);
  }
  return pending;
}

async function appendUniqueLogLines(logPath, logLines) {
  const existingContents = await readLogContents(logPath);
  const pending = selectUnloggedLines(existingContents, logLines);
  if (pending.length === 0) return 0;

  const newline = existingContents.includes('\r\n') ? '\r\n' : '\n';
  const separator = existingContents.length > 0 && !/(?:\r?\n)$/u.test(existingContents)
    ? newline
    : '';
  await appendFile(logPath, `${separator}${pending.join(newline)}${newline}`, 'utf8');
  return pending.length;
}

export async function processFixture({ root, now = new Date() }) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'privilege.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('privilege 경보 묶음 형식이 아닙니다.');
  }

  const result = processAlerts(fixture.alerts, now);
  const loggedAlerts = await appendUniqueLogLines(join(root, 'xdr', 'alerts.log'), result.logLines);
  return { ...result, loggedAlerts, actualTrafficBlocked: false };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const result = await processFixture({ root });
    process.stdout.write(`${JSON.stringify({
      counts: result.counts,
      denyCandidates: result.denyCandidates.map(({ alertId, expiresAt }) => ({ alertId, expiresAt })),
      loggedAlerts: result.loggedAlerts,
      actualTrafficBlocked: result.actualTrafficBlocked,
    })}\n`);
    process.stdout.write('차단 후보는 연습용이며 ZTNA 판정기에 자동 적용되지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 첫 오류: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
