import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);

function redactSecretLikeText(value) {
  return String(value ?? '').replace(
    /\b(password|passwd|token|secret|api[_ -]?key|private[_ -]?key)\b\s*[:=]\s*[^\s,;]+/gi,
    '$1=[redacted]',
  );
}

export function extractAlertRows(fixture) {
  if (!Array.isArray(fixture?.alerts)) {
    throw new TypeError('경보 파일에 alerts 배열이 없습니다.');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: redactSecretLikeText(alert?.timestamp),
    sourceAddress: redactSecretLikeText(alert?.data?.srcip),
    account: redactSecretLikeText(alert?.data?.srcuser),
    ruleLevel: redactSecretLikeText(alert?.rule?.level),
    description: redactSecretLikeText(alert?.rule?.description),
  }));
}

export function formatAlertRows(rows) {
  return rows.map(({ timestamp, sourceAddress, account, ruleLevel, description }) =>
    [timestamp, sourceAddress, account, ruleLevel, description].join(' | '),
  );
}

async function main() {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const rows = extractAlertRows(fixture);
  const lines = formatAlertRows(rows);

  for (const line of lines) console.log(line);
  console.log(`경보 ${fixture.alerts.length}건 / 추출 줄 ${lines.length}줄`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(`경보 읽기 실패: ${error.message}`);
    process.exitCode = 1;
  });
}
