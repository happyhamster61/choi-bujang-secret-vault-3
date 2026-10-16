import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { decide } from '../xdr/privilege/decide.mjs';
import { extractAlertRows, formatAlertRows } from '../xdr/privilege/read-alerts.mjs';
import { buildResponsePlan, activeAccountDenials, revokeBlockedSessions,
  createDenyCandidate } from '../xdr/privilege/respond.mjs';
const fixture=JSON.parse(readFileSync(new URL('../xdr/fixtures/privilege.json',import.meta.url)));
const normal=fixture.alerts.filter(a=>a.rule.mitre.length===0);
const review=fixture.alerts.filter(a=>a.rule.mitre.length>0&&a.rule.level>=5&&a.rule.level<10);
const clear=fixture.alerts.filter(a=>a.rule.level>=10);

test('실습 내용 기준 명확한 공격·확인 필요·정상 경보를 각각 구분한다',()=>{
  for(const [alerts,action] of [[clear,'block'],[review,'alert'],[normal,'record']]){
    for(const alert of alerts){const d=decide(alert);assert.equal(d.action,action,alert.rule.description);
      assert.ok(d.confidence>=0&&d.confidence<=1);assert.ok(!/[\r\n]/.test(d.reason));
      assert.equal(d.action,d.confidence>=0.85?'block':d.confidence>=0.5?'alert':'record');}
  }
  assert.equal(clear.length+review.length+normal.length,fixture.alerts.length);
});
test('읽기 모듈은 경보마다 한 줄을 만들고 비밀값을 가린다',()=>{
  assert.equal(formatAlertRows(extractAlertRows(fixture)).length,fixture.alerts.length);
  const copy=structuredClone(fixture);copy.alerts[0].rule.description='token=synthetic-secret-value';
  assert.ok(!formatAlertRows(extractAlertRows(copy))[0].includes('synthetic-secret-value'));
});
test('판단 파일은 단독·오프라인 실행되며 ID·계정명·주소·배열 순서에 의존하지 않는다',()=>{
  const source=readFileSync(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/\bimport\s*(?:\(|[{'"*])|\brequire\s*\(|\bfetch\s*\(|\bprocess\.|readFile|writeFile/);
  const isolated=runInNewContext(source.replace('export function decide','function decide')+'; decide',{});
  for(const [i,alert] of [...fixture.alerts].reverse().entries()){
    const copy=structuredClone(alert);copy.id='renamed-'+i;copy.data.srcip='192.0.2.200';copy.data.srcuser='synthetic-'+i;
    assert.equal(isolated(copy).action,decide(alert).action);
  }
});
test('태그·높은 수준·IP 단독으로는 정상 경보를 차단하지 않는다',()=>{
  for(const alert of normal){assert.equal(decide({...alert,rule:{...alert.rule,level:12}}).action,'record');}
  assert.equal(decide({timestamp:'2026-10-16T00:00:00Z',data:{srcuser:'synthetic'},
    rule:{level:12,mitre:['T1078'],description:'판단할 행위 정보가 없습니다.'}}).action,'record');
  assert.equal(decide(null).action,'record');
});
test('차단 후보와 세션 회수는 명확한 계정에만 적용하고 다른 계정·만료 규칙은 제외한다',async()=>{
  const now=new Date('2026-10-16T00:00:00Z');
  const plan=await buildResponsePlan(fixture.alerts,{now});
  assert.deepEqual(plan.counts,{block:9,alert:8,record:9});
  assert.equal(plan.denyCandidates.length,clear.length);
  assert.equal(plan.alertEntries.length,review.length);
  assert.ok(plan.denyCandidates.every(r=>clear.some(a=>a.id===r.alertId)));
  for(const alert of normal)assert.equal(createDenyCandidate(alert,decide(alert),now),null);
  assert.equal(activeAccountDenials('unrelated-account',plan.denyCandidates,now).length,0);
  assert.equal(activeAccountDenials(clear[0].data.srcuser,plan.denyCandidates,
    new Date(now.getTime()+30*60*1000)).length,0);
  const calls=[];
  const result=await revokeBlockedSessions(plan,{
    now,resolveVerifiedSessions:async account=>[{id:'session-'+account,account},
      {id:'unrelated-session',account:'unrelated-account'}],
    revokeSession:async id=>calls.push(id),
  });
  assert.equal(result.revokedCount,new Set(clear.map(a=>a.data.srcuser)).size);
  assert.ok(!calls.includes('unrelated-session'));
});

test('내장 패턴의 이름·조건·근거는 patterns.json과 일치한다',()=>{
  const source=readFileSync(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
  const metadata=runInNewContext(source.replace('export function decide','function decide')+
    '; PATTERNS.map(({name,condition,mitre,evidence})=>({name,condition,mitre,evidence}))',{});
  const patterns=JSON.parse(readFileSync(new URL('../xdr/privilege/patterns.json',import.meta.url))).patterns;
  assert.deepEqual(JSON.parse(JSON.stringify(metadata)),patterns);
});

test('Wazuh MITRE id 배열 형식도 같은 의미로 분류한다',()=>{
  for(const alert of fixture.alerts){
    const copy=structuredClone(alert);copy.rule.mitre={id:copy.rule.mitre.map(x=>' '+x.toLowerCase()+' ')};
    assert.equal(decide(copy).action,decide(alert).action);
  }
});
