import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { createAuthHandler } from '../api/auth.js';
const env={SUPABASE_URL:'https://auth.example.invalid',SUPABASE_SECRET_KEY:'server-only-test-key'};
const request=(body={email:'test@example.invalid',password:'synthetic'},extra={})=>({
  method:'POST',headers:{'content-type':'application/json'},body,...extra});
function response(){return {code:0,body:null,headers:{},setHeader(k,v){this.headers[k]=v;},
  status(c){this.code=c;return this;},json(b){this.body=b;return this;}};}
function factory(signIn,signOut=async()=>({error:null})){
  return (_url,_key,options)=>{
    assert.equal(options.auth.persistSession,false);
    assert.equal(options.auth.autoRefreshToken,false);
    return {auth:{signInWithPassword:signIn,admin:{signOut}}};
  };
}
test('서버 로그인은 필요한 세션 필드만 반환하고 비밀키·갱신 토큰·사용자 메타데이터를 노출하지 않는다',async()=>{
  let clients=0;
  const base=factory(async input=>{
    assert.deepEqual(input,{email:'test@example.invalid',password:'synthetic'});
    return {data:{session:{access_token:'synthetic-access',refresh_token:'private-refresh',
      expires_at:2000000000,user:{id:'synthetic-user',email:input.email,user_metadata:{admin:true}}}}};
  });
  const handler=createAuthHandler({env,clientFactory:(...a)=>{clients++;return base(...a);}});
  for(let i=0;i<2;i++){
    const res=response();await handler(request(),res);
    assert.equal(res.code,200);
    assert.equal(res.headers['Cache-Control'],'no-store');
    assert.deepEqual(res.body,{session:{access_token:'synthetic-access',expires_at:2000000000,user:{id:'synthetic-user'}}});
    assert.ok(!JSON.stringify(res.body).includes(env.SUPABASE_SECRET_KEY));
  }
  assert.equal(clients,2);
});
test('잘못된 로그인·외부 출처·지원하지 않는 메서드는 안전하게 거부한다',async()=>{
  let calls=0;
  const handler=createAuthHandler({env,clientFactory:factory(async()=>{calls++;return {error:{status:400,message:'sensitive upstream detail'}};})});
  for(const [req,expected] of [
    [request(null),400],[request({email:'bad',password:'x'}),400],
    [request({email:'test@example.invalid',password:'x',role:'admin'}),400],
    [request(undefined,{headers:{'content-type':'text/plain'}}),415],
    [request(undefined,{headers:{origin:'https://evil.invalid',host:'app.vercel.app'}}),403],
    [request(undefined,{method:'GET'}),405],
  ]){const res=response();await handler(req,res);assert.equal(res.code,expected);}
  assert.equal(calls,0);
  const res=response();await handler(request(),res);assert.equal(res.code,401);
  assert.deepEqual(res.body,{error:'INVALID_CREDENTIALS'});
});
test('로그아웃은 요청의 Bearer만 사용해 해당 세션을 종료한다',async()=>{
  const handler=createAuthHandler({env,clientFactory:factory(async()=>{throw Error('unexpected');},async(token,scope)=>{
    assert.equal(token,'synthetic-access');assert.equal(scope,'local');return {error:null};
  })});
  const missing=response();await handler({method:'DELETE',headers:{}},missing);assert.equal(missing.code,401);
  const res=response();await handler({method:'DELETE',headers:{authorization:'Bearer synthetic-access'}},res);
  assert.equal(res.code,200);assert.deepEqual(res.body,{signedOut:true});
});
test('인증 서비스 설정 누락·네트워크 실패는 성공 응답으로 바꾸지 않는다',async()=>{
  const missing=response();await createAuthHandler({env:{}})(request(),missing);assert.equal(missing.code,503);
  const res=response();await createAuthHandler({env,clientFactory:()=>{throw Error('sensitive detail');}})(request(),res);
  assert.equal(res.code,502);assert.deepEqual(res.body,{error:'AUTH_UNAVAILABLE'});
});
test('공개 화면에는 Supabase 키·SDK가 없고 로그인·로그아웃은 같은 출처의 서버 함수를 호출한다',()=>{
  function scan(dir){for(const file of readdirSync(dir,{withFileTypes:true})){
    const path=new URL(file.name+(file.isDirectory()?'/':''),dir);
    if(file.isDirectory())scan(path);
    else if(/\.(html|js|json|webmanifest)$/.test(file.name)){
      const text=readFileSync(path,'utf8');
      assert.doesNotMatch(text,/sb_publishable_[A-Za-z0-9_-]+|sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
    }
  }}scan(new URL('../public/',import.meta.url));
  const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  assert.doesNotMatch(html,/@supabase|window\.supabase|localStorage|sessionStorage|indexedDB/);
  assert.match(html,/fetch\('\/api\/auth'/);assert.match(html,/method: 'DELETE'/);
  assert.match(html,/sessionExpiryTimer/);
});
