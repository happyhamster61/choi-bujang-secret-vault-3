// 9단계 가상 탐지 전용: 엔진이 검증해 전달한 사건만 받습니다.
// 개인정보·토큰·기기·네트워크·지역은 읽거나 기록하지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const THRESHOLD = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  for (const event of events) {
    // The published event contract exposes only at, method, identity.sub.
    const at = event?.at;
    const method = event?.method;
    const sub = event?.identity?.sub;
    if (method !== 'GET' || typeof sub !== 'string' || sub.length === 0
        || typeof at !== 'string') continue;
    const timestamp = Date.parse(at);
    if (!Number.isFinite(timestamp)) continue;
    const times = readsBySubject.get(sub);
    if (times) times.push(timestamp);
    else readsBySubject.set(sub, [timestamp]);
  }

  // Check every possible 10-minute window, including unsorted input streams.
  for (const [subject, times] of readsBySubject) {
    if (times.length <= THRESHOLD) continue;
    times.sort((a, b) => a - b);
    for (let end = THRESHOLD; end < times.length; end += 1) {
      if (times[end] - times[end - THRESHOLD] <= WINDOW_MS) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
      }
    }
  }
  return { action: 'observe' };
}
