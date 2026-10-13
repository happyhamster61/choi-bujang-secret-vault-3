import { appendFile, readFile } from 'node:fs/promises';
import { decide } from './decide.mjs';

const RULE_TTL_MS = 30 * 60 * 1000;

function redactSecretLikeText(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[redacted private key]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(/\b(password|passwd|pwd|token|access[_ -]?token|refresh[_ -]?token|secret(?:[_ -]?key)?|api[_ -]?key|private[_ -]?key|access[_ -]?key|authorization|cookie|credential)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi, '$1$2[redacted]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted key]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/[\r\n]+/g, ' ');
}

function validateDecision(result, alertId) {
  if (!result || !['block', 'alert', 'record'].includes(result.action)
      || typeof result.confidence !== 'number'
      || !Number.isFinite(result.confidence)
      || result.confidence < 0 || result.confidence > 1
      || typeof result.reason !== 'string') {
    throw new TypeError(`지원하지 않는 decide 결과: ${alertId || '(id 없음)'}`);
  }
}

function createDenyCandidate(alert, result, now) {
  if (result.action !== 'block' || result.confidence < 0.85) return null;

  const alertId = alert?.id;
  const sourceAddress = alert?.data?.srcip;
  if (typeof alertId !== 'string' || !alertId.trim()
      || typeof sourceAddress !== 'string' || !sourceAddress.trim()) return null;

  return {
    effect: 'deny',
    sourceAddress,
    alertId,
    confidence: result.confidence,
    reason: redactSecretLikeText(result.reason),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
  };
}

async function readExistingLog(logPath) {
  try {
    return await readFile(logPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return '';
    throw error;
  }
}

function collectLoggedIds(contents) {
  const ids = new Set();
  for (const line of contents.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (typeof entry?.alertId === 'string') ids.add(entry.alertId);
    } catch {
      // Preserve old or malformed rows; they cannot be safely deduplicated.
    }
  }
  return ids;
}

/** Process explicitly supplied fixture alerts; deny candidates are returned, never applied. */
export async function respondAlerts({ alerts, logPath, now = new Date() } = {}) {
  if (!Array.isArray(alerts)) throw new TypeError('alerts 배열을 명시적으로 전달해야 합니다.');
  if (typeof logPath !== 'string' || !logPath.trim()) {
    throw new TypeError('로그 기록 경로 logPath를 명시적으로 전달해야 합니다.');
  }
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('유효한 생성 시각 Date를 전달해야 합니다.');
  }

  const counts = { block: 0, alert: 0, record: 0 };
  const denyCandidates = [];
  const logLines = [];
  const candidateIds = new Set();
  const existingLog = await readExistingLog(logPath);
  const loggedIds = collectLoggedIds(existingLog);

  for (const alert of alerts) {
    const result = decide(alert);
    const alertId = alert?.id;
    validateDecision(result, alertId);
    counts[result.action] += 1;

    const candidate = createDenyCandidate(alert, result, now);
    if (candidate && !candidateIds.has(candidate.alertId)) {
      denyCandidates.push(candidate);
      candidateIds.add(candidate.alertId);
    }

    if (typeof alertId !== 'string' || !alertId.trim()) {
      throw new TypeError('경보에 기록할 id가 없습니다.');
    }
    if (!loggedIds.has(alertId)) {
      logLines.push(JSON.stringify({
        alertId,
        action: result.action,
        reason: redactSecretLikeText(result.reason),
      }));
      loggedIds.add(alertId);
    }
  }

  if (logLines.length > 0) {
    const separator = existingLog && !/(?:\r?\n)$/.test(existingLog) ? '\n' : '';
    await appendFile(logPath, `${separator}${logLines.join('\n')}\n`, 'utf8');
  }

  return {
    counts,
    denyCandidates,
    loggedAlerts: logLines.length,
    actualTrafficBlocked: false,
  };
}
