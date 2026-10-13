const PATTERNS = Object.freeze({
  unsignedService: Object.freeze({
    name: '서명 없는 서비스 등록 흔적',
    reasonName: '서명 없는 서비스 등록 흔적',
    limitation: ' (서명 상태는 전용 필드가 아니라 경보 설명에 기록된 내용을 근거로 함)',
    conditions: "rule.mitre에 T1543이 있고, (rule.description에 '서명 없는 새 서비스'가 포함되며 data.path가 AppData\\Local\\Temp 아래이거나, rule.description에 '서명 없는 서비스 등록'이 포함되며 data.count를 숫자로 변환한 값이 3 이상)입니다.",
    evidence: 'ps-01은 T1543, 설명의 미서명 서비스 주장과 Temp 경로를, ps-04는 T1543, 설명의 미서명 등록 주장과 count 3을 기록합니다. 서명 여부는 전용 필드가 아니라 설명으로만 확인됩니다.',
  }),
  scheduledTask: Object.freeze({
    name: '평소 목록에 없던 예약 작업 의심',
    reasonName: '평소 목록에 없던 예약 작업 의심',
    limitation: '',
    conditions: "rule.mitre에 T1053이 있고 data.path가 AppData\\Local\\Temp 아래이며, rule.description에 '처음 보는 예약 작업' 또는 '예약 작업 이름이 임의 문자열' 중 하나가 포함됩니다.",
    evidence: 'ps-02와 ps-05는 각각 해당 예약 작업 설명, Temp 경로, T1053 태그를 함께 기록합니다. 평소 목록은 구조화된 자료로 제공되지 않아 설명의 표현을 탐지 단서로 사용합니다.',
  }),
  startupItem: Object.freeze({
    name: '시작 폴더에 새 항목 추가 흔적',
    reasonName: '시작 폴더에 새 항목 추가 흔적',
    limitation: ' (fixture의 MITRE T1543 태그와 시작 폴더의 ATT&CK 분류 차이는 별도 한계로 유지)',
    conditions: "rule.mitre에 T1543이 있고 rule.description에 '시작 폴더에 평소 목록에 없는 프로그램'이 포함되며 data.path가 \\Start Menu\\Programs\\Startup\\ 아래입니다.",
    evidence: 'ps-03은 설명과 Startup 경로 및 T1543 태그를 기록합니다. 설명의 목록 외 주장은 독립 필드로 검증되지 않고, Startup Folder의 ATT&CK 분류와 fixture 태그 사이에는 차이가 있습니다.',
  }),
  changedUnsignedService: Object.freeze({
    name: '변경된 미서명 서비스 실행 파일',
    reasonName: '변경된 미서명 서비스 실행 파일',
    limitation: ' (서명 상태는 전용 필드가 아니라 경보 설명에 기록된 내용을 근거로 함)',
    conditions: "rule.mitre에 T1543이 있고 rule.description에 '서비스 실행 파일이 바뀌었고 서명이 없습니다'가 포함되며 data.path가 AppData\\Local\\Temp 아래입니다.",
    evidence: 'ps-06은 T1543과 Temp 경로가 필드로 기록되고, 실행 파일 변경 및 서명 없음은 설명에 기록됩니다.',
  }),
  sharedTempPersistence: Object.freeze({
    name: '서비스와 예약 작업의 동일 임시 파일 사용',
    reasonName: '서비스와 예약 작업의 동일 임시 파일 사용',
    limitation: '',
    conditions: "rule.mitre에 T1543과 T1053이 모두 있고 rule.description에 '시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킵니다'가 포함되며 data.path가 AppData\\Local\\Temp 아래입니다.",
    evidence: 'ps-07은 두 MITRE 태그와 Temp 경로를 필드로 기록합니다. 두 지속성 방식이 같은 파일을 가리킨다는 관계는 설명 문구에 기록됩니다.',
  }),
  unlistedPersistentService: Object.freeze({
    name: '목록 외 서비스의 재부팅 후 지속',
    reasonName: '목록 외 서비스의 재부팅 후 지속',
    limitation: ' (기준 목록과의 대조는 별도 필드가 아니라 경보 설명에 기록된 내용을 근거로 함)',
    conditions: "rule.mitre에 T1543이 있고 rule.level이 10 이상이며 rule.description에 '평소 목록에 없는 서비스가 다시 켜도 남도록 등록됐습니다'가 포함되고 data.path가 AppData\\Local\\Temp 아래입니다.",
    evidence: 'ps-08은 T1543, level 12, Temp 경로와 해당 설명을 함께 기록합니다. 미등록 여부와 재시작 후 지속 주장은 독립적인 구조화 필드가 아니라 설명에만 있어 별도로 검증되지 않습니다.',
  }),
  tempExecutableNoService: Object.freeze({
    name: '서비스 미등록 상태의 임시 실행 파일',
    reasonName: '서비스 미등록 상태의 임시 실행 파일',
    limitation: '',
    conditions: "공통으로 rule.level이 5 이상이고, rule.mitre에 T1543이 있으며 rule.level이 8 이상, rule.description에 '임시 폴더에 실행 파일이 하나 생겼습니다'와 '서비스 등록은 없습니다'가 모두 포함되고 data.path가 AppData\\Local\\Temp 아래입니다.",
    evidence: 'ps-13은 규칙 수준, T1543 태그, Temp 경로와 설명을 기록하지만 설명상 서비스 등록은 없습니다. 따라서 강한 서비스 등록 근거가 아닌 애매한 신호로 다룹니다.',
  }),
  ambiguousScheduledTask: Object.freeze({
    name: '검증이 덜 된 예약 작업 흔적',
    reasonName: '검증이 덜 된 예약 작업 흔적',
    limitation: '',
    conditions: "공통으로 rule.level이 5 이상이고 rule.mitre에 T1053이 있으며, (설명에 '수업 중 예약 작업을 하나 만들었습니다'와 '서명은 확인되지 않았습니다'가 모두 포함되거나, '예약 작업이 하나 있고 실행 시각은 수업 시간'이 포함되거나, '예약 작업 이름이 수업 과제와 비슷'과 '만든 사람은'이 모두 포함됩니다.)",
    evidence: 'ps-09, ps-12, ps-15는 T1053과 해당 설명을 기록하지만 서명 미확인·수업 시간·과제 유사 이름만으로 악성임을 확정할 수 없어 alert 신호로 사용합니다.',
  }),
  ambiguousStartup: Object.freeze({
    name: '확인되지 않은 시작 항목 변경',
    reasonName: '확인되지 않은 시작 항목 변경',
    limitation: '',
    conditions: "공통으로 rule.level이 5 이상이고 rule.mitre에 T1543이 있으며, (설명에 '시작 항목에 수업 도구 이름이 하나 있습니다'와 '서명은 아직 모릅니다'가 모두 포함되거나, '시작 폴더 변경이 1건입니다'와 '이어서 실행된 기록은 없습니다'가 모두 포함됩니다.)",
    evidence: 'ps-10과 ps-14는 T1543 및 설명의 시작 항목 단서를 기록하지만 서명·실행 여부가 확인되지 않아 alert 수준의 신호입니다.',
  }),
  ambiguousService: Object.freeze({
    name: '확인이 더 필요한 서비스 흔적',
    reasonName: '확인이 더 필요한 서비스 흔적',
    limitation: '',
    conditions: "공통으로 rule.level이 5 이상이고 rule.mitre에 T1543이 있으며, 설명에 (목록 외 서비스가 재시작 뒤 남는다는 문구와 data.path의 Temp 경로가 함께 있거나, '서비스 설명만 한 번 바뀌었습니다'와 '실행 파일은 그대로입니다'가 모두 있거나, '서비스가 한 번 멈췄다가 같은 파일로 다시 시작됐습니다'가 포함됩니다.) 강한 조건이 먼저 평가됩니다.",
    evidence: 'ps-08, ps-11, ps-16은 T1543과 설명의 서비스 단서를 기록합니다. ps-08은 강한 조건에도 맞아 강한 분기가 우선하며, 나머지 설명만으로는 악성 서비스 등록을 독립 검증할 수 없어 alert 신호로 둡니다.',
  }),
});

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
    return PATTERNS.changedUnsignedService;
  }

  if (hasTechnique(alert, 'T1543')
      && hasTechnique(alert, 'T1053')
      && description.includes('시작 프로그램과 예약 작업이 같은 임시 파일을 함께 가리킵니다')
      && isTempPath(path)) {
    return PATTERNS.sharedTempPersistence;
  }

  if (hasTechnique(alert, 'T1543')
      && levelOf(alert) >= 10
      && description.includes('평소 목록에 없는 서비스가 다시 켜도 남도록 등록됐습니다')
      && isTempPath(path)) {
    return PATTERNS.unlistedPersistentService;
  }

  if (hasTechnique(alert, 'T1543')
      && ((description.includes('서명 없는 새 서비스') && isTempPath(path))
        || (description.includes('서명 없는 서비스 등록') && Number.isFinite(count) && count >= 3))) {
    return PATTERNS.unsignedService;
  }

  if (hasTechnique(alert, 'T1053') && isTempPath(path)
      && (description.includes('처음 보는 예약 작업')
        || description.includes('예약 작업 이름이 임의 문자열'))) {
    return PATTERNS.scheduledTask;
  }

  if (hasTechnique(alert, 'T1543')
      && description.includes('시작 폴더에 평소 목록에 없는 프로그램')
      && /\\Start Menu\\Programs\\Startup\\/i.test(path)) {
    return PATTERNS.startupItem;
  }

  return null;
}

function ambiguousSignalsOf(alert) {
  const level = levelOf(alert);
  if (level < 5) return false;
  const description = descriptionOf(alert);
  const unregisteredTempExecutable = hasTechnique(alert, 'T1543')
    && level >= 8
    && description.includes('임시 폴더에 실행 파일이 하나 생겼습니다')
    && description.includes('서비스 등록은 없습니다')
    && isTempPath(pathOf(alert));
  const taskSignal = hasTechnique(alert, 'T1053') && (
    (description.includes('수업 중 예약 작업을 하나 만들었습니다')
      && description.includes('서명은 확인되지 않았습니다'))
    || description.includes('예약 작업이 하나 있고 실행 시각은 수업 시간')
    || (description.includes('예약 작업 이름이 수업 과제와 비슷')
      && description.includes('만든 사람은'))
  );
  const startupSignal = hasTechnique(alert, 'T1543') && (
    (description.includes('시작 항목에 수업 도구 이름이 하나 있습니다')
      && description.includes('서명은 아직 모릅니다'))
    || (description.includes('시작 폴더 변경이 1건입니다')
      && description.includes('이어서 실행된 기록은 없습니다'))
  );
  const serviceSignal = hasTechnique(alert, 'T1543')
    && (
      (description.includes('평소 목록에 없는 서비스가 다시 켜도 남도록 등록됐습니다')
        && isTempPath(pathOf(alert)))
      || (description.includes('서비스 설명만 한 번 바뀌었습니다')
        && description.includes('실행 파일은 그대로입니다'))
      || description.includes('서비스가 한 번 멈췄다가 같은 파일로 다시 시작됐습니다')
    );
  return {
    unregisteredTempExecutable,
    taskSignal,
    startupSignal,
    serviceSignal,
    matched: unregisteredTempExecutable || taskSignal || startupSignal || serviceSignal,
  };
}

export function decide(alert) {
  const strongPattern = findStrongPattern(alert);
  if (strongPattern) {
    let limitation = '';
    limitation = strongPattern.limitation;
    return makeDecision(CONFIDENCE.block, `${strongPattern.reasonName}: 경보의 기법·설명과 요청된 보조 필드가 함께 일치함${limitation}`);
  }

  const ambiguousSignals = ambiguousSignalsOf(alert);
  if (ambiguousSignals.matched) {
    const description = descriptionOf(alert);
    const pattern = hasTechnique(alert, 'T1053') && /예약 작업/.test(description)
      ? PATTERNS.ambiguousScheduledTask
      : /시작 (?:폴더|항목|프로그램)/.test(description)
        ? PATTERNS.ambiguousStartup
        : ambiguousSignals.unregisteredTempExecutable
          ? PATTERNS.tempExecutableNoService
          : PATTERNS.ambiguousService;
    return makeDecision(CONFIDENCE.alert, `${pattern.reasonName}: 관련 ATT&CK 태그와 설명은 있으나 강한 패턴 조건이 충족되지 않음`);
  }

  return makeDecision(CONFIDENCE.record, '일치 패턴 없음: 정상 이벤트이거나 지속성 악용 근거가 부족함');
}
