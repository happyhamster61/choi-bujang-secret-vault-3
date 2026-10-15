import { createHash, createPublicKey, verify } from 'node:crypto';
import { NotesAccessError } from './notes-service.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NONCE = /^[a-f0-9]{32}$/u;
const B64URL = /^[A-Za-z0-9_-]{80,200}$/u;

export function validPublicDeviceKey(jwk) {
  return jwk && typeof jwk === 'object' && !Array.isArray(jwk)
    && Object.keys(jwk).sort().join(',') === 'crv,kty,x,y'
    && jwk.kty === 'EC' && jwk.crv === 'P-256'
    && typeof jwk.x === 'string' && typeof jwk.y === 'string'
    && /^[A-Za-z0-9_-]{43}$/u.test(jwk.x)
    && /^[A-Za-z0-9_-]{43}$/u.test(jwk.y);
}

export function deviceSignaturePayload(method, path, body, time, nonce) {
  const rawBody = typeof body === 'string' ? body :
    body == null ? '' : JSON.stringify(body);
  const hash = createHash('sha256').update(rawBody).digest('hex');
  return [method, path, hash, time, nonce].join('\n');
}

export function verifyDeviceProof({ method, path, body, time, nonce,
  signature, publicJwk, now = Date.now() }) {
  if (!validPublicDeviceKey(publicJwk) || typeof method !== 'string'
      || typeof path !== 'string'
      || typeof time !== 'string' || !/^\d{13}$/u.test(time)
      || Math.abs(now - Number(time)) > 120000
      || typeof nonce !== 'string' || !NONCE.test(nonce)
      || typeof signature !== 'string' || !B64URL.test(signature)) return false;
  try {
    const pub = createPublicKey({ key: publicJwk, format: 'jwk' });
    return verify('sha256',
      Buffer.from(deviceSignaturePayload(method, path, body, time, nonce)),
      { key: pub, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'));
  } catch { return false; }
}

export async function requireApprovedDevice(request, userId, supabase) {
  const id = request.headers?.['x-device-id'];
  const time = request.headers?.['x-device-time'];
  const nonce = request.headers?.['x-device-nonce'];
  const signature = request.headers?.['x-device-signature'];
  if (typeof id !== 'string' || !UUID.test(id)) {
    throw new NotesAccessError(403, 'DEVICE_APPROVAL_REQUIRED');
  }
  const { data: device, error } = await supabase.from('stage11_devices')
    .select('public_jwk,status').eq('device_id',id)
    .eq('owner_id',userId).maybeSingle();
  if (error) throw new NotesAccessError(503,'DEVICE_CHECK_UNAVAILABLE');
  if (!device || device.status !== 'approved') {
    throw new NotesAccessError(403,'DEVICE_APPROVAL_REQUIRED');
  }
  const url = new URL(request.url, 'https://localhost');
  if (!verifyDeviceProof({ method: request.method,
      path: url.pathname+url.search, body: request.body,
      time, nonce, signature, publicJwk: device.public_jwk })) {
    throw new NotesAccessError(403,'DEVICE_PROOF_INVALID');
  }
  // Unique insert makes nonce replay fail closed, across serverless instances.
  const { error: nonceError } = await supabase.from('stage11_device_nonces')
    .insert({ device_id:id,nonce });
  if (nonceError) throw new NotesAccessError(403,'DEVICE_REPLAY_DENIED');
}
