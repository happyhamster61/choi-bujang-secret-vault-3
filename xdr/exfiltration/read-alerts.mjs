import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/exfiltration.json', import.meta.url);
const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|token|access[_ -]?token|refresh[_ -]?token|secret|api[_ -]?key|private[_ -]?key|authorization|cookie|credential)\b(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi;

function redactSecretLikeText(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[redacted private key]')
    .replace(/\bBearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
    .replace(SECRET_ASSIGNMENT, '$1$2[redacted]')
    .replace(/\bsb_(?:secret|publishable)_[A-Za-z0-9_-]+\b/g, '[redacted key]')
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted key]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/[\r\n]+/g, ' ');
}

function requireText(value, field, index) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`경보 ${index + 1}건의 ${field} 필드가 없거나 문자열이 아닙니다.`);
  }
  return value;
}

export function extractAlertRows(fixture) {
  if (!Array.isArray(fixture?.alerts) || fixture.alerts.length === 0) {
    throw new TypeError('경보 파일에 비어 있지 않은 alerts 배열이 없습니다.');
  }

  return fixture.alerts.map((alert, index) => {
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
      throw new TypeError(`경보 ${index + 1}건의 구조가 객체가 아닙니다.`);
    }
    if (!alert.data || typeof alert.data !== 'object' || Array.isArray(alert.data)) {
      throw new TypeError(`경보 ${index + 1}건의 data 구조가 없습니다.`);
    }
    if (!alert.rule || typeof alert.rule !== 'object' || Array.isArray(alert.rule)) {
      throw new TypeError(`경보 ${index + 1}건의 rule 구조가 없습니다.`);
    }

    const level = alert.rule.level;
    if (!(typeof level === 'number' && Number.isFinite(level))
        && !(typeof level === 'string' && level.trim() !== '' && Number.isFinite(Number(level)))) {
      throw new TypeError(`경보 ${index + 1}건의 rule.level 필드가 없거나 숫자가 아닙니다.`);
    }

    return {
      timestamp: redactSecretLikeText(requireText(alert.timestamp, 'timestamp', index)),
      sourceAddress: redactSecretLikeText(requireText(alert.data.srcip, 'data.srcip', index)),
      account: redactSecretLikeText(requireText(alert.data.srcuser, 'data.srcuser', index)),
      ruleLevel: redactSecretLikeText(level),
      description: redactSecretLikeText(requireText(alert.rule.description, 'rule.description', index)),
    };
  });
}

export function formatAlertRows(rows) {
  return rows.map(({ timestamp, sourceAddress, account, ruleLevel, description }) =>
    [timestamp, sourceAddress, account, ruleLevel, description].join(' | '),
  );
}

async function main() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'exfiltration') {
    throw new TypeError('exfiltration 경보 fixture의 schema 또는 moduleKey가 올바르지 않습니다.');
  }

  const rows = extractAlertRows(fixture);
  const lines = formatAlertRows(rows);
  if (lines.length !== fixture.alerts.length) {
    throw new Error(`경보 수와 출력 줄 수가 다릅니다: 경보 ${fixture.alerts.length}건 / 출력 ${lines.length}줄`);
  }

  for (const line of lines) console.log(line);
  console.log(`경보 ${fixture.alerts.length}건 / 출력 ${lines.length}줄`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(`경보 읽기 실패: ${error instanceof Error ? error.message : '알 수 없는 오류'}`);
    process.exitCode = 1;
  });
}
