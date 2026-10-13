const PATTERNS = Object.freeze([
  Object.freeze({
    name: '서명 없는 서비스 등록 흔적',
    conditions: "rule.mitre에 T1543이 있고 rule.description에 '서명 없는 새 서비스' 또는 '서명 없는 서비스 등록'이 명시됩니다. data.path가 있으면 실행 파일 위치를 보조 근거로 사용하되 필수 조건으로 삼지 않습니다.",
    evidence: 'ps-01은 서명 없는 새 서비스와 임시 폴더 실행 파일을, ps-04는 서명 없는 서비스 등록 3건을 설명하며 둘 다 T1543입니다. 서명 상태 전용 필드와 서비스 이름은 없어 설명에 기록된 신호만 확인할 수 있습니다.',
  }),
  Object.freeze({
    name: '평소 목록에 없던 예약 작업 의심',
    conditions: "rule.mitre에 T1053이 있고 (rule.description에 '처음 보는 예약 작업'이 명시되고 data.path가 임시 폴더 아래이거나, 설명에 '예약 작업 이름이 임의 문자열'이 명시되고 data.path가 임시 폴더 아래입니다.)",
    evidence: 'ps-02는 처음 보는 예약 작업이 임시 폴더 프로그램을 실행한다고 기록하고 ps-05는 임의 문자열 이름과 임시 폴더 실행 파일을 함께 기록하며 둘 다 T1053입니다. 평소 목록 자체는 fixture에 없어 설명의 표현을 탐색 단서로만 사용합니다.',
  }),
  Object.freeze({
    name: '시작 폴더에 새 항목 추가 흔적',
    conditions: 'rule.mitre에 T1543이 있고 rule.description에 시작 폴더에 평소 목록에 없는 프로그램이 명시되며 data.path가 Windows Start Menu\\Programs\\Startup 경로 아래입니다.',
    evidence: 'ps-03은 해당 설명과 Startup 경로를 기록하고 fixture 태그는 T1543입니다. 다만 MITRE ATT&CK에서는 Startup Folder가 T1547.001이므로 이 태그와 ATT&CK 분류가 일치하지 않는 한계를 나타냅니다.',
  }),
]);

const CONFIDENCE = Object.freeze({ block: 0.9, alert: 0.65, record: 0.1 });

function makeDecision(confidence, reason) {
  const action = confidence >= 0.85
    ? 'block'
    : confidence >= 0.5
      ? 'alert'
      : 'record';
  return { action, confidence, reason: String(reason).replace(/[\r\n]+/g, ' ') };
}

function descriptionOf(alert) {
  return typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
}

function hasTechnique(alert, technique) {
  return Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes(technique);
}

function levelOf(alert) {
  const level = alert?.rule?.level;
  return typeof level === 'number' && Number.isFinite(level) ? level : Number.NaN;
}

function pathOf(alert) {
  return typeof alert?.data?.path === 'string' ? alert.data.path : '';
}

function isTempPath(path) {
  return /\\AppData\\Local\\Temp\\/i.test(path);
}

function findStrongPattern(alert) {
  const description = descriptionOf(alert);
  const path = pathOf(alert);
  const count = Number(alert?.data?.count);

  if (hasTechnique(alert, 'T1543')
      && description.includes('서비스 실행 파일이 바뀌었고 서명이 없습니다')
      && isTempPath(path)) {
    return PATTERNS[0];
  }

  if (hasTechnique(alert, 'T1543')
      && hasTechnique(alert, 'T1053')
      && description.includes('시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킵니다')
      && isTempPath(path)) {
    return PATTERNS[1];
  }

  if (hasTechnique(alert, 'T1543')
      && ((description.includes('서명 없는 새 서비스') && isTempPath(path))
        || (description.includes('서명 없는 서비스 등록') && Number.isFinite(count) && count >= 3))) {
    return PATTERNS[0];
  }

  if (hasTechnique(alert, 'T1053') && isTempPath(path)
      && (description.includes('처음 보는 예약 작업')
        || description.includes('예약 작업 이름이 임의 문자열'))) {
    return PATTERNS[1];
  }

  if (hasTechnique(alert, 'T1543')
      && description.includes('시작 폴더에 평소 목록에 없는 프로그램')
      && /\\Start Menu\\Programs\\Startup\\/i.test(path)) {
    return PATTERNS[2];
  }

  return null;
}

function hasAmbiguousPersistenceSignal(alert) {
  const level = levelOf(alert);
  if (level < 5) return false;
  const description = descriptionOf(alert);
  const unregisteredTempExecutable = hasTechnique(alert, 'T1543')
    && level >= 8
    && description.includes('임시 폴더에 실행 파일이 하나 생겼습니다')
    && description.includes('서비스 등록은 없습니다')
    && isTempPath(pathOf(alert));
  const taskSignal = hasTechnique(alert, 'T1053') && /예약 작업/.test(description);
  const startupSignal = /시작 (?:폴더|항목|프로그램)/.test(description);
  const serviceSignal = hasTechnique(alert, 'T1543')
    && /서비스/.test(description)
    && !/서비스 등록은 없습니다/.test(description);
  return unregisteredTempExecutable || taskSignal || startupSignal || serviceSignal;
}

export function decide(alert) {
  const strongPattern = findStrongPattern(alert);
  if (strongPattern) {
    let limitation = '';
    if (strongPattern === PATTERNS[0]) {
      limitation = ' (서명 상태는 전용 필드가 아니라 경보 설명에 기록된 내용을 근거로 함)';
    }
    if (strongPattern === PATTERNS[2]) {
      limitation = ' (fixture의 MITRE T1543 태그와 시작 폴더의 ATT&CK 분류 차이는 별도 한계로 유지)';
    }
    return makeDecision(CONFIDENCE.block, `${strongPattern.name}: 경보의 기법·설명과 요청된 보조 필드가 함께 일치함${limitation}`);
  }

  if (hasAmbiguousPersistenceSignal(alert)) {
    const description = descriptionOf(alert);
    const pattern = hasTechnique(alert, 'T1053') && /예약 작업/.test(description)
      ? PATTERNS[1]
      : /시작 (?:폴더|항목|프로그램)/.test(description)
        ? PATTERNS[2]
        : PATTERNS[0];
    return makeDecision(CONFIDENCE.alert, `${pattern.name}: 관련 ATT&CK 태그와 설명은 있으나 강한 패턴 조건이 충족되지 않음`);
  }

  return makeDecision(CONFIDENCE.record, '일치 패턴 없음: 정상 이벤트이거나 지속성 악용 근거가 부족함');
}
