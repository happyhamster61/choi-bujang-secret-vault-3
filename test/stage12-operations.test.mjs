import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import operations from '../api/operations.js';
import { unexecutedChallengeCases, sanitizeCheck, summarizeChecks, stageVerificationChecks, buildEvidenceGroups
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

test('제출 미실행·작전실 HTTP·과거 단계 검사·공식 41종을 서로 다른 집합으로 유지한다',()=>{
  const probe=sanitizeCheck({id:'dashboard-probe',name:'별도 API',expected:'HTTP 401',
    observed:'HTTP 401 LOGIN_REQUIRED',requestId:'student-probe',checkedAt:'2026-10-16T00:00:00Z',
    status:'observed',source:'live_http_response'});
  const attempts=[{attackId:'notes_list_without_login',expected:'HTTP 401 LOGIN_REQUIRED',observed:'not_run'}];
  const groups=buildEvidenceGroups({probe,submissionAttempts:attempts,deploymentCommit:'a'.repeat(40)});
  assert.deepEqual(Object.keys(groups),['submission','dashboardApi','stageVerification','officialChallenges']);
  assert.equal(groups.submission.checks[0].status,'not_run');
  assert.equal(groups.submission.checks[0].observed,null);
  assert.equal(groups.submission.checks[0].requestId,null);
  assert.equal(groups.dashboardApi.checks[0].observed,probe.observed);
  assert.equal(groups.officialChallenges.summary.unexecuted,41);
  assert.equal(groups.stageVerification.checks.length,22);
  assert.ok(groups.stageVerification.checks.every(r=>r.testedCommit==='0201e0b21546034283d12baffa05e63c007d1b9e'));
  assert.equal(attempts[0].observed,'not_run');
  assert.throws(()=>buildEvidenceGroups({probe,submissionAttempts:[{...attempts[0],observed:'HTTP 401 LOGIN_REQUIRED'}]}));
});
test('1~11단계는 로컬·운영 API의 기대값과 실제값을 각각 기록한다',()=>{
  const checks=stageVerificationChecks();
  for(let stage=1;stage<=11;stage++){
    const rows=checks.filter(r=>r.stage===stage);assert.equal(rows.length,2);
    assert.ok(rows.every(r=>r.expected.length>0));
    for(const row of rows){
      if(row.status==='observed'){assert.ok(row.observed);assert.ok(row.checkedAt);}
      else {assert.equal(row.observed,null);assert.equal(row.checkedAt,null);assert.equal(row.requestId,null);}
    }
  }
  assert.throws(()=>sanitizeCheck({status:'observed',observed:'HTTP 200'}));
  assert.throws(()=>sanitizeCheck({status:'not_run',observed:'HTTP 401 LOGIN_REQUIRED'}));
});

test('작전실 렌더링은 별도 API 401을 제출 미실행 행으로 복사하지 않는다',async()=>{
  const {runInNewContext}=await import('node:vm');
  function element(){return {children:[],textContent:'',hidden:false,disabled:false,
    append(...children){this.children.push(...children);},
    replaceChildren(...children){this.children=children;},
    setAttribute(){},addEventListener(){}};}
  const nodes=new Map();
  const document={querySelector(id){if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);},
    createElement:()=>element()};
  const probe=sanitizeCheck({id:'separate-probe',name:'별도 API',expected:'HTTP 401',
    observed:'HTTP 401 LOGIN_REQUIRED',requestId:'probe-only',checkedAt:'2026-10-16T00:00:00Z',
    status:'observed',source:'live_http_response'});
  const groups=buildEvidenceGroups({probe,submissionAttempts:[{attackId:'notes_list_without_login',expected:'HTTP 401',observed:'not_run'}],deploymentCommit:'a'.repeat(40)});
  const report={schema:'byteback.operations.v1',checkedAt:'2026-10-16T00:00:00Z',deploymentCommit:'a'.repeat(40),
    evidence:{checks:[probe],groups}};
  const source=readFileSync(new URL('../public/operations-dashboard.js',import.meta.url),'utf8');
  const mount=runInNewContext(source.replace('export function mountOperationsDashboard','function mountOperationsDashboard')+'; mountOperationsDashboard',{document});
  const dashboard=mount({getSession:()=>({access_token:'synthetic-only'}),deviceGate:{isApproved:()=>true,
    signedFetch:async()=>({ok:true,json:async()=>report})}});
  await dashboard.reload();
  const rows=nodes.get('#operations-checks').children;
  const submission=rows.find(r=>r.children[0]?.textContent==='notes_list_without_login');
  const live=rows.find(r=>r.children[0]?.textContent==='separate-probe');
  assert.equal(submission.children[3].textContent,'미실행');
  assert.equal(submission.children[4].textContent,'—');
  assert.equal(live.children[3].textContent,'HTTP 401 LOGIN_REQUIRED');
  assert.equal(live.children[4].textContent,'probe-only');
  assert.equal(rows.filter(r=>r.children.length===1&&r.children[0].colSpan===9).length,4);
});

test('실제 제출 점검 11건은 작전실에서도 미실행이며 공식 41종과 분리된다', async () => {
  const { runAttackChecks } = await import('../src/attack-check.mjs');
  const attempts = await runAttackChecks({ step: 12, publicAppUrl: 'https://student-defense.vercel.app' });
  const probe = sanitizeCheck({ id:'probe', status:'not_run', expected:'HTTP 401' });
  const groups = buildEvidenceGroups({ probe, submissionAttempts:attempts, deploymentCommit:'a'.repeat(40) });
  assert.equal(groups.submission.checks.length,11);
  assert.deepEqual(groups.submission.summary,{observed:0,unexecuted:11,unavailable:0});
  assert.ok(groups.submission.checks.every(row=>row.observed===null&&row.requestId===null));
  assert.equal(groups.officialChallenges.checks.length,41);
  assert.equal(groups.officialChallenges.summary.unexecuted,41);
});

test('HTTP 관측 집계는 성공 문구와 응답 없는 실패를 관측으로 세지 않는다', () => {
  const row={id:'probe',expected:'HTTP 401',observed:'성공했습니다',status:'observed',
    source:'live_http_response',checkedAt:'2026-10-16T00:00:00Z',requestId:'student-only'};
  assert.throws(()=>summarizeChecks([row]),/missing_http_response_evidence/);
  assert.throws(()=>sanitizeCheck({...row,observed:'HTTP 401',requestId:null}));
  assert.throws(()=>sanitizeCheck({...row,status:'unavailable',observed:'HTTP 401'}));
  assert.deepEqual(summarizeChecks([{...row,observed:'HTTP 500'}]),{observed:1,unexecuted:0,unavailable:0});
});
