import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { deviceSignaturePayload, validPublicDeviceKey,
  verifyDeviceProof, requireApprovedDevice } from '../src/device-proof.mjs';

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicJwk = publicKey.export({ format: 'jwk' });
const jwk = { crv: publicJwk.crv, kty: publicJwk.kty,
  x: publicJwk.x, y: publicJwk.y };
const path = '/api/notes/fixture';
const method = 'PUT';
const body = JSON.stringify({title:'virtual',body:'simulated'});
const time = String(Date.now());
const nonce = 'ab'.repeat(16);
const signature = sign('sha256',
  Buffer.from(deviceSignaturePayload(method,path,body,time,nonce)),
  {key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');

test('기기 키는 P-256 공개키만 등록할 수 있고 비밀 값은 거부한다', () => {
  assert.equal(validPublicDeviceKey(jwk),true);
  assert.equal(validPublicDeviceKey({...jwk,d:'private-key'}),false);
});
test('서명된 메서드·경로·수정 본문·시각만 통과한다', () => {
  const proof={method,path,body,time,nonce,signature,publicJwk:jwk,
    now:Number(time)};
  assert.equal(verifyDeviceProof(proof),true);
  assert.equal(verifyDeviceProof({...proof,path:'/api/notes/other'}),false);
  assert.equal(verifyDeviceProof({...proof,method:'DELETE'}),false);
  assert.equal(verifyDeviceProof({...proof,body:JSON.stringify({title:'changed'})}),false);
  assert.equal(verifyDeviceProof({...proof,time:String(Number(time)-300000)}),false);
  assert.equal(verifyDeviceProof({...proof,publicJwk:{...jwk,x:'x'.repeat(43)}}),false);
});
test('서버 미승인·다른 소유자·무서명 요청은 보호 자료에 접근하지 못한다', async () => {
  function database(owner,status) {
    return { from(table) {
      if(table === 'stage11_devices') return {
        select(){return this;},eq(key,value){this[key]=value;return this;},
        async maybeSingle(){return {data: owner==='user1'?
          {status,public_jwk:jwk}:null,error:null}}
      };
      throw Error('unexpected nonce table');
    }};
  }
  const deviceId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const req={url:path,method,body,headers:{'x-device-id':deviceId,
    'x-device-time':time,'x-device-nonce':nonce,'x-device-signature':signature}};
  await assert.rejects(requireApprovedDevice(req,'user1',database('user1','pending')),
    {status:403,code:'DEVICE_APPROVAL_REQUIRED'});
  await assert.rejects(requireApprovedDevice(req,'user2',database('user2','approved')),
    {status:403,code:'DEVICE_APPROVAL_REQUIRED'});
  await assert.rejects(requireApprovedDevice({...req,headers:{}},'user1',
    database('user1','approved')),{status:403,code:'DEVICE_APPROVAL_REQUIRED'});
});
test('설치형 UI는 인증 지속 저장을 끄고 개인키를 저장소에 기록하지 않는다', () => {
  const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  const ui=readFileSync(new URL('../public/device-client.js',import.meta.url),'utf8');
  assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB|window\.supabase/);
  assert.match(html, /showSession\(null\)/);
  assert.match(html,/deviceGate.isApproved\(\)/);
  assert.match(html,/deviceGate.signedFetch/);
  assert.doesNotMatch(ui,/(localStorage|sessionStorage|indexedDB)\s*[.(]/);
  const script=html.match(/<script type="module">([\s\S]*?)<\/script>/);
  assert.ok(script);
  assert.doesNotThrow(() => new Function('return (async () => { '+
    script[1].replace(/^\s*import .*;\s*$/mg,'')+' })'));
});
