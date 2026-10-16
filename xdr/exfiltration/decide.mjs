const PATTERNS = Object.freeze([
  {
    "name": "낯선 목적지 대량 반출",
    "condition": "T1041 또는 T1048, 실제 전송 설명, 목적지와 처음 보는 주소 단서, 50MB 이상 또는 파일 50개 이상이 함께 있는 경우",
    "mitre": [
      "T1041",
      "T1048"
    ],
    "evidence": "T1041·T1048의 외부 반출 행위를 낯선 목적지와 전송 규모로 보강한 로컬 정책이며, 50MB·50개는 MITRE가 정한 기준이 아닙니다."
  },
  {
    "name": "시간 외 압축 파일 반출",
    "condition": "T1041 또는 T1048, 실제 전송·압축 파일·업무 또는 수업 시간 밖 설명, 목적지와 50MB 이상 전송이 함께 있는 경우",
    "mitre": [
      "T1041",
      "T1048"
    ],
    "evidence": "외부 반출 경보의 압축 파일과 명시적 시간 외 설명을 함께 확인하며 실제 업무 시간표를 임의로 만들지 않습니다."
  },
  {
    "name": "반복 대용량 전송",
    "condition": "T1041 또는 T1048, 목적지와 실제 전송 설명, 전송량 50MB 이상 및 반복 횟수 5회 이상이 함께 있는 경우",
    "mitre": [
      "T1041",
      "T1048"
    ],
    "evidence": "명령 통로나 대체 통로를 통한 반복 반출을 전송 규모와 횟수로 보강하며 5회는 로컬 정책 기준입니다."
  },
  {
    "name": "비정상 통로 대량 반출",
    "condition": "T1048, 평소 쓰지 않던 포트 설명, 실제 전송과 목적지, 50MB 이상 또는 파일 50개 이상이 함께 있는 경우",
    "mitre": [
      "T1048"
    ],
    "evidence": "T1048의 대체 프로토콜 반출에 대응하는 통로 이상 단서이며 포트 번호나 프로토콜이 주어지지 않으면 추정하지 않습니다."
  },
  {
    "name": "자료실 전체 외부 복사",
    "condition": "T1041 또는 T1048, 자료실 전체를 외부로 복사했다는 설명, 목적지와 50MB 이상 또는 파일 50개 이상이 함께 있는 경우",
    "mitre": [
      "T1041",
      "T1048"
    ],
    "evidence": "외부 반출의 광범위한 자료 접근과 실제 복사를 함께 확인하며 태그나 전송량 하나만으로는 차단하지 않습니다."
  },
  {
    "name": "반출 확인 필요",
    "condition": "T1041 또는 T1048과 전송·압축·목적지 관련 단서가 있으나 차단 패턴의 근거가 부족한 중간 이상 수준 경보. 실패·미전송은 차단하지 않고 알림만 기록",
    "mitre": [
      "T1041",
      "T1048"
    ],
    "evidence": "태그가 붙은 준비·실패·일회성·소량 전송은 성공한 대량 유출로 확정할 수 없어 alert로만 남깁니다. 낮은 수준의 일상 읽기·동기화는 record로 둡니다."
  }
].map(pattern => Object.freeze({ ...pattern, mitre: Object.freeze(pattern.mitre) })));

// Local training thresholds, not universal exfiltration or MITRE thresholds.
const LARGE_BYTES = 50_000_000;
const MANY_FILES = 50;
const REPEATED_TRANSFERS = 5;
function number(value) {
  if (typeof value !== 'number' && !(typeof value === 'string' && /^\d+$/.test(value))) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}
function answer(confidence, patterns) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: patterns.length ? patterns.map(p => p.name).join('; ') : '일치 패턴 없음: 일상 이벤트 또는 근거 부족' };
}
export function decide(alert) {
  const text = typeof alert?.rule?.description === 'string'
    ? alert.rule.description.replace(/\s+/g,' ').trim() : '';
  const raw = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : alert?.rule?.mitre?.id;
  const techniques = Array.isArray(raw) ? raw.filter(x => typeof x === 'string')
    .map(x => x.trim().toUpperCase()) : [];
  const has = id => techniques.some(t => t === id || t.startsWith(id + '.'));
  const relevant = has('T1041') || has('T1048');
  const level = number(alert?.rule?.level);
  if (!text || level === null || !relevant) return answer(0.05, []);
  const bytes = number(alert?.data?.bytes);
  const files = number(alert?.data?.files);
  const count = number(alert?.data?.count);
  const destination = typeof alert?.data?.dstip === 'string' && !!alert.data.dstip.trim();
  const large = (bytes !== null && bytes >= LARGE_BYTES) || (files !== null && files >= MANY_FILES);
  const largeBytes = bytes !== null && bytes >= LARGE_BYTES;
  const repeated = count !== null && count >= REPEATED_TRANSFERS;
  const unfamiliar = /처음\s*(?:보는|봅니다)|낯선|새로운\s*목적지|unfamiliar|first[- ]seen/i.test(text);
  const archive = /압축\s*파일|archive|\bzip\b/i.test(text);
  const outsideHours = /(?:업무|수업)\s*시간\s*(?:밖|외)|outside (?:work|business) hours/i.test(text);
  const unusualChannel = /평소.{0,15}쓰지\s*않던\s*포트|비정상\s*(?:포트|통로)|unusual port/i.test(text);
  const fullCopy = /자료실\s*전체.{0,20}외부.{0,20}복사|entire repository.{0,30}(?:external|copied)/i.test(text);
  const unsuccessful = /(?:외부\s*)?전송(?:은|이)?\s*(?:아직\s*)?(?:없|실패)|전송.{0,12}취소|전송되지\s*않|not (?:sent|transferred)|transfer failed/i.test(text);
  const sent = !unsuccessful && bytes !== 0 && /나갔|올라갔|복사됐|전송됐|전송되었습니다|전송했습니다|전송이\s*\d+번|전송.{0,12}반복|uploaded|transferred|copied/i.test(text);
  const matches = [];
  if (destination && sent) {
    if (unfamiliar && large) matches.push(PATTERNS[0]);
    if (outsideHours && archive && largeBytes) matches.push(PATTERNS[1]);
    if (largeBytes && repeated) matches.push(PATTERNS[2]);
    if (has('T1048') && unusualChannel && large) matches.push(PATTERNS[3]);
    if (fullCopy && large) matches.push(PATTERNS[4]);
  }
  if (matches.length) return answer(level >= 10 ? 0.95 : 0.9, matches);
  const reviewContext = /전송|압축|파일|자료|목적지|주소|명령\s*통로|transfer|archive|destination/i.test(text);
  if (level >= 5 && reviewContext) return answer(0.65, [PATTERNS[5]]);
  return answer(0.1, []);
}
