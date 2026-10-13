import { appendFile, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULE_TTL_MS = 30 * 60 * 1000;

function redactSecretLikeText(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[redacted private key]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(/\b(password|passwd|pwd|token|access[_ -]?token|refresh[_ -]?token|secret|api[_ -]?key|private[_ -]?key|authorization|cookie|credential)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi, '$1$2[redacted]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted key]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/[\r\n]+/g, ' ');
}

function cleanField(value) {
  return typeof value === 'string' && value.trim() ? redactSecretLikeText(value.trim()) : null;
}

function validDecision(decision) {
  return Boolean(decision)
    && ['block', 'alert', 'record'].includes(decision.action)
    && typeof decision.confidence === 'number'
    && Number.isFinite(decision.confidence)
    && decision.confidence >= 0
    && decision.confidence <= 1
    && typeof decision.reason === 'string';
}

export function createDenyCandidate(alert, decision, now = new Date()) {
  if (!validDecision(decision) || decision.action !== 'block' || decision.confidence < 0.85) return null;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new TypeError('차단 후보 생성 시각이 올바르지 않습니다.');
  }

  const alertId = cleanField(alert?.id);
  const sourceAddress = cleanField(alert?.data?.srcip);
  if (!alertId || !sourceAddress) return null;

  return {
    effect: 'deny',
    sourceAddress,
    account: cleanField(alert?.data?.srcuser),
    alertId,
    expiresAt: new Date(now.getTime() + RULE_TTL_MS).toISOString(),
    reason: redactSecretLikeText(decision.reason),
  };
}

export function createAlertLogEntry(alert, decision) {
  if (!validDecision(decision) || decision.action !== 'alert') return null;
  const alertId = cleanField(alert?.id);
  if (!alertId) return null;
  return {
    alertId,
    action: 'alert',
    confidence: decision.confidence,
    reason: redactSecretLikeText(decision.reason),
    account: cleanField(alert?.data?.srcuser),
    sourceAddress: cleanField(alert?.data?.srcip),
  };
}

export async function buildResponsePlan(alerts, { now = new Date(), decideAlert = decide } = {}) {
  if (!Array.isArray(alerts)) throw new TypeError('alerts는 배열이어야 합니다.');
  const counts = { block: 0, alert: 0, record: 0 };
  const denyCandidates = [];
  const alertEntries = [];
  const decisions = [];

  for (const alert of alerts) {
    const decision = await decideAlert(alert);
    if (!validDecision(decision)) {
      throw new Error(`지원하지 않는 decide 결과: ${alert?.id ?? '(id 없음)'}`);
    }
    counts[decision.action] += 1;
    decisions.push({ alertId: cleanField(alert?.id), ...decision });

    const candidate = createDenyCandidate(alert, decision, now);
    if (candidate) denyCandidates.push(candidate);
    const logEntry = createAlertLogEntry(alert, decision);
    if (logEntry) alertEntries.push(logEntry);
  }

  return { counts, decisions, denyCandidates, alertEntries };
}

async function readTextOrEmpty(path) {
  try {
    return await readFile(path, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return '';
    throw error;
  }
}

async function appendNewAlertEntries(logPath, entries) {
  if (entries.length === 0) return 0;
  const previous = await readTextOrEmpty(logPath);
  const knownIds = new Set();
  for (const line of previous.split(/\r?\n/u)) {
    try {
      const row = JSON.parse(line);
      if (row?.action === 'alert' && typeof row.alertId === 'string') knownIds.add(row.alertId);
    } catch {
      // Leave pre-existing non-JSON or malformed lines untouched.
    }
  }

  const additions = entries.filter((entry) => !knownIds.has(entry.alertId));
  if (additions.length === 0) return 0;
  const separator = previous.length > 0 && !previous.endsWith('\n') ? '\n' : '';
  await appendFile(logPath, `${separator}${additions.map((entry) => JSON.stringify(entry)).join('\n')}\n`, 'utf8');
  return additions.length;
}

async function mergeDenyCandidates(candidatePath, candidates) {
  let prior = { schema: 'aleph.xdr.deny-candidates.v1', rules: [] };
  const existing = await readTextOrEmpty(candidatePath);
  if (existing.trim()) {
    const parsed = JSON.parse(existing);
    if (parsed?.schema !== 'aleph.xdr.deny-candidates.v1' || !Array.isArray(parsed.rules)) {
      throw new Error('기존 deny 후보 파일 형식이 올바르지 않아 보존을 위해 갱신을 중단합니다.');
    }
    prior = parsed;
  }

  const rules = [...prior.rules];
  const knownIds = new Set(rules.map((rule) => rule?.alertId).filter((id) => typeof id === 'string'));
  for (const candidate of candidates) {
    if (knownIds.has(candidate.alertId)) continue;
    rules.push(candidate);
    knownIds.add(candidate.alertId);
  }

  const temporaryPath = `${candidatePath}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify({ schema: prior.schema, rules }, null, 2)}\n`, 'utf8');
    await rename(temporaryPath, candidatePath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
  return rules.length - prior.rules.length;
}

export async function processFixture({ root, now = new Date() }) {
  const fixturePath = join(root, 'xdr', 'fixtures', 'privilege.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('privilege 경보 묶음 형식이 아닙니다.');
  }

  const plan = await buildResponsePlan(fixture.alerts, { now });
  const denyRulesPath = join(root, 'xdr', 'privilege', 'deny-rules.json');
  const alertsLogPath = join(root, 'xdr', 'alerts.log');
  const addedCandidates = await mergeDenyCandidates(denyRulesPath, plan.denyCandidates);
  const loggedAlerts = await appendNewAlertEntries(alertsLogPath, plan.alertEntries);
  return { ...plan, addedCandidates, loggedAlerts };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const result = await processFixture({ root });
    process.stdout.write(`${JSON.stringify({ counts: result.counts, denyCandidates: result.denyCandidates.length, addedCandidates: result.addedCandidates, loggedAlerts: result.loggedAlerts })}\n`);
    process.stdout.write('차단 후보는 연습용 기록이며 실제 ZTNA 규칙이나 트래픽을 변경하지 않습니다.\n');
  } catch (error) {
    process.stderr.write(`응답 처리 실패: ${error instanceof Error ? error.message : '실행 오류'}\n`);
    process.exitCode = 1;
  }
}
