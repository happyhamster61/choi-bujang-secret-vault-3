// Stage 11: private signing keys exist only in JS memory (never localStorage/IndexedDB).
export function createDeviceGate({ getSession, onChange }) {
  const section = document.querySelector('#device-section');
  const status = document.querySelector('#device-status');
  const requestButton = document.querySelector('#device-request');
  const checkButton = document.querySelector('#device-check');
  const offline = document.querySelector('#offline-status');
  const installButton = document.querySelector('#install-app');
  const encoder = new TextEncoder();
  let keyPair = null;
  let deviceId = null;
  let approved = false;
  let currentUser = null;
  let installPrompt = null;

  function reset(user = null) {
    currentUser = user;
    keyPair = null;
    deviceId = null;
    approved = false;
    checkButton.hidden = true;
    status.textContent = '서버에 기기 승인을 요청해 주세요.';
  }
  function setSession(session) {
    const user = session?.user?.id ?? null;
    if (user !== currentUser) reset(user);
    section.hidden = !user;
  }
  function isApproved() {
    return approved && navigator.onLine && Boolean(keyPair && deviceId);
  }
  function base64url(bytes) {
    let raw = '';
    for (const b of bytes) raw += String.fromCharCode(b);
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  async function signatureHeaders(method, path, body = '') {
    if (!keyPair || !deviceId) throw new Error('기기 승인 요청이 필요합니다.');
    const stamp = String(Date.now());
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
      x => x.toString(16).padStart(2, '0')).join('');
    const hashed = await crypto.subtle.digest('SHA-256', encoder.encode(body));
    const hash = Array.from(new Uint8Array(hashed),
      x => x.toString(16).padStart(2, '0')).join('');
    const message = [method, path, hash, stamp, nonce].join('\n');
    const signed = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey,
      encoder.encode(message));
    return {
      'X-Device-Id': deviceId, 'X-Device-Time': stamp,
      'X-Device-Nonce': nonce,
      'X-Device-Signature': base64url(new Uint8Array(signed))
    };
  }
  async function signedFetch(path, options = {}) {
    const session = getSession();
    if (!isApproved() || !session?.access_token) {
      throw new Error('서버가 승인한 기기의 요청만 허용합니다.');
    }
    const method = options.method ?? 'GET';
    const body = options.body ?? '';
    const proof = await signatureHeaders(method, path, body);
    return fetch(path, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: 'Bearer ' + session.access_token, ...proof
      }
    });
  }
  async function refresh() { await onChange(); }
  requestButton.addEventListener('click', async () => {
    const session = getSession();
    if (!session?.access_token || !navigator.onLine) return;
    requestButton.disabled = true;
    approved = false;
    await refresh();
    status.textContent = '승인 요청을 서버에 보내는 중입니다.';
    try {
      // Non-extractable private key. Reloading the page discards it.
      keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const res = await fetch('/api/device', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + session.access_token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ publicJwk: {
          kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y
        } })
      });
      if (!res.ok) throw new Error('기기 등록 요청이 거부되었습니다.');
      const data = await res.json();
      deviceId = data.deviceId;
      checkButton.hidden = false;
      status.textContent = '승인 대기 중입니다. 관리자 확인 후 상태를 다시 확인하세요.';
    } catch (error) {
      reset(currentUser);
      status.textContent = error.message;
    } finally { requestButton.disabled = false; }
  });
  checkButton.addEventListener('click', async () => {
    const session = getSession();
    if (!session?.access_token || !keyPair || !deviceId) return;
    checkButton.disabled = true;
    try {
      const path = '/api/device?id=' + encodeURIComponent(deviceId);
      const proof = await signatureHeaders('GET', path);
      const res = await fetch(path, {
        cache: 'no-store',
        headers: { Authorization: 'Bearer ' + session.access_token, ...proof }
      });
      if (!res.ok) throw new Error('서버 기기 확인에 실패했습니다.');
      const data = await res.json();
      approved = data.approved === true && data.status === 'approved';
      status.textContent = approved ?
        '서버 승인과 기기 서명을 확인했습니다. 자료실을 엽니다.' :
        '승인 대기 중입니다. 승인 버튼만으로 권한은 부여되지 않습니다.';
      await refresh();
    } catch (error) {
      approved = false;
      status.textContent = error.message;
      await refresh();
    } finally { checkButton.disabled = false; }
  });
  const updateNetwork = () => {
    offline.textContent = navigator.onLine
      ? '온라인 연결됨. 기기 승인과 요청 서명은 별도 확인합니다.'
      : '오프라인: 보호 메모는 표시하지 않습니다.';
    if (!navigator.onLine) {
      approved = false;
      void refresh();
    }
  };
  addEventListener('online', updateNetwork);
  addEventListener('offline', updateNetwork);
  updateNetwork();
  addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    installPrompt = event;
    installButton.hidden = false;
  });
  installButton.addEventListener('click', async () => {
    if (!installPrompt) return;
    await installPrompt.prompt();
    installPrompt = null;
    installButton.hidden = true;
  });
  return { isApproved, signedFetch, setSession };
}
