import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import operations from '../api/operations.js';
import { unexecutedChallengeCases, sanitizeCheck, summarizeChecks
} from '../src/operations-report.mjs';

function response() {
  let status; let body; const headers = {};
  const res = {
    setHeader(k,v){headers[k.toLowerCase()] = v; return this;},
    status(code){status=code;return this;},
    json(result){body=result;return this;}
  };
  return {res, result:()=>({status,body,headers})};
}
test('공식 공격 41종은 실제 실행 로그 없이 모두 미실행으로 둔다',()=>{
  const rows=unexecutedChallengeCases();
  assert.equal(rows.length,41);
  assert.equal(new Set(rows.map(x=>x.id)).size,41);
  assert.ok(rows.every(x=>x.status==='not_run'&&x.observed===null
    &&x.requestId===null&&x.checkedAt===null));
  assert.deepEqual(summarizeChecks(rows),
    {observed:0,unexecuted:41,unavailable:0});
});
test('실제 HTTP 결과가 있는 경우에만 관측으로 분류한다',()=>{
  const row=sanitizeCheck({id:'live1',name:'anonymous',expected:'401',
    observed:'HTTP 401 LOGIN_REQUIRED',requestId:'req-1',
    checkedAt:'2026-10-15T00:00:00.000Z',status:'observed',
    source:'live_http_response'});
  assert.equal(row.status,'observed');
  assert.equal(row.requestId,'req-1');
  assert.throws(()=>sanitizeCheck({...row,status:'passed'}));
});
test('작전실 API는 무로그인 접근을 차단하고 GET만 허용한다',async()=>{
  const get=response();
  await operations({method:'GET',url:'/api/operations',headers:{}},get.res);
  assert.equal(get.result().status,401);
  assert.equal(get.result().body.error,'LOGIN_REQUIRED');
  assert.equal(get.result().headers['cache-control'],'no-store');
  const post=response();
  await operations({method:'POST',headers:{}},post.res);
  assert.equal(post.result().status,405);
});
test('작전실 UI에는 본문이 아닌 상태 필드만 표시되고 서명한 GET을 사용한다',()=>{
  const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
  const js=readFileSync(new URL('../public/operations-dashboard.js',import.meta.url),'utf8');
  assert.match(html,/탈환 작전실/);
  assert.match(html,/operations-checks/);
  assert.match(js,/deviceGate\.signedFetch\('\/api\/operations'/);
  assert.doesNotMatch(js,/localStorage|sessionStorage|indexedDB/);
  assert.doesNotMatch(js,/note\.body|note\.content/);
});
