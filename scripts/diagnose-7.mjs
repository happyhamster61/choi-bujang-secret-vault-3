import { fixtureRequests } from './fixture-7.mjs';
import { decide } from '../src/decider.mjs';

const { normal, suspicious } = fixtureRequests();

function copy(value) {
  return structuredClone(value);
}

const sourceNone = copy(suspicious);
sourceNone.signals.source = 'none';

const hourNormal = copy(suspicious);
hourNormal.signals.hour = 14;

const networkUsual = copy(suspicious);
networkUsual.signals.network = 'usual';

const eventNotRead = copy(suspicious);
eventNotRead.recentEvents[0].kind = 'login';

const countBelowLocalPolicy = copy(suspicious);
countBelowLocalPolicy.recentEvents[0].count = 7;

const eventOutsideLocalWindow = copy(suspicious);
eventOutsideLocalWindow.recentEvents[0].ageSeconds = 301;

const scenarios = [
  { label: '정상 fixture 기준선', changed: '변경 없음', request: normal },
  { label: '복합 fixture 기준선', changed: '변경 없음', request: suspicious },
  { label: 'source만 none', changed: 'signals.source', request: sourceNone },
  { label: 'hour만 정상 시각', changed: 'signals.hour → 14', request: hourNormal },
  { label: 'network만 usual', changed: 'signals.network → usual', request: networkUsual },
  { label: 'kind만 login', changed: 'recentEvents[0].kind → login', request: eventNotRead },
  { label: 'count만 감소', changed: 'recentEvents[0].count → 7', request: countBelowLocalPolicy },
  { label: 'ageSeconds만 변경', changed: 'recentEvents[0].ageSeconds → 301', request: eventOutsideLocalWindow },
];

const baselineSuspiciousDecision = decide(suspicious).decision;
const rows = scenarios.map(({ label, changed, request }) => {
  const result = decide(request);
  return {
    scenario: label,
    changed,
    decision: result.decision,
    reasonCode: result.reasonCode,
    changedVerdict: request === normal || request === suspicious
      ? '기준선'
      : result.decision !== baselineSuspiciousDecision,
  };
});

console.log('ALEPH 7단계 로컬 진단 — scripts/fixture-7.mjs 복제 입력만 사용');
console.table(rows);
console.log(`복합 fixture 기준선: ${baselineSuspiciousDecision}`);
console.log('단일 변경 결과(복합 fixture 기준선 대비):');
for (const row of rows.slice(2)) {
  console.log(`- ${row.changed}: ${row.decision}${row.changedVerdict ? ' (step_up에서 allow로 변경)' : ''}`);
}
console.log('\n주의: source:none 및 각 변형은 로컬 원인 분리용 입력이며 실제 심판 입력이라는 뜻이 아닙니다.');
