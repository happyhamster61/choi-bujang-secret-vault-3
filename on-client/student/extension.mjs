// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions } = {}) {
      const root = document.createElement('section');
      root.setAttribute('aria-label', '로그인 사용자·기기·세션');

      const heading = document.createElement('h3');
      heading.textContent = '로그인 사용자·기기·세션';
      root.append(heading);

      const modeText = (resource) => {
        const mode = resource?.mode ?? resource?.meta?.mode ?? 'unknown';
        if (mode === 'demo') return '예제 자료';
        if (mode === 'disconnected') return '연결 없음';
        if (mode === 'unknown') return '확인 불가';
        return '';
      };

      const statusText = (resource) => {
        if (resource?.status === 'loading') return '불러오는 중';
        if (resource?.status === 'error') {
          const message = typeof resource.error?.message === 'string' && resource.error.message
            ? resource.error.message
            : '오류 내용을 확인할 수 없습니다.';
          return `연결 실패: ${message}`;
        }
        if (resource?.status !== 'ok') return '확인 불가: 입력 상태를 확인할 수 없습니다.';
        return null;
      };

      const addRow = (title, resource, valueForOk) => {
        const label = document.createElement('h4');
        label.textContent = title;
        root.append(label);

        const value = document.createElement('p');
        const message = statusText(resource);
        if (message !== null) {
          value.textContent = message;
        } else {
          value.textContent = valueForOk();
        }
        root.append(value);

        const mode = modeText(resource);
        if (mode) {
          const modeNote = document.createElement('p');
          modeNote.textContent = mode;
          root.append(modeNote);
        }
      };

      const idText = (value) => typeof value === 'string' && value ? value : '확인 불가';
      const labelAndId = (item) => {
        const label = typeof item?.label === 'string' && item.label ? item.label : idText(item?.id);
        return `${label} (ID: ${idText(item?.id)})`;
      };
      const deviceStatus = (status) => ({
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      })[status] ?? '확인 불가';
      const sessionStatus = (status) => ({
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      })[status] ?? '확인 불가';

      addRow('계정', me, () => {
        const user = me.data?.user;
        return user ? labelAndId(user) : '확인 불가: 사용자 정보를 받지 못했습니다.';
      });

      addRow('현재 기기', devices, () => {
        if (me?.status === 'loading') return '불러오는 중: 현재 사용자 정보를 기다리고 있습니다.';
        if (me?.status === 'error') return '확인 불가: 현재 사용자 정보를 확인할 수 없습니다.';
        const current = me?.status === 'ok' ? me.data?.device : null;
        if (!current) return '확인 불가: 현재 기기 정보를 받지 못했습니다.';
        const listed = Array.isArray(devices.data)
          ? devices.data.find((item) => item?.id === current.id)
          : null;
        const device = listed ?? current;
        return `${labelAndId(device)} · ${deviceStatus(device.status)}`;
      });

      addRow('현재 세션', sessions, () => {
        if (me?.status === 'loading') return '불러오는 중: 현재 사용자 정보를 기다리고 있습니다.';
        if (me?.status === 'error') return '확인 불가: 현재 사용자 정보를 확인할 수 없습니다.';
        const current = me?.status === 'ok' ? me.data?.session : null;
        if (!current) return '확인 불가: 현재 세션 정보를 받지 못했습니다.';
        const listed = Array.isArray(sessions.data)
          ? sessions.data.find((item) => item?.id === current.id)
          : null;
        const session = listed ?? current;
        return `${idText(session.id)} · ${sessionStatus(session.status)}`;
      });

      return root;
    },
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
