import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { extractAlertRows, formatAlertRows } from '../xdr/exfiltration/read-alerts.mjs';
import { buildResponsePlan, createDenyCandidate, activeDestinationDenials,
  applyDestinationBlocks, processFixture } from '../xdr/exfiltration/respond.mjs';
const fixture=JSON.parse(readFileSync(new URL('../xdr/fixtures/exfiltration.json',import.meta.url)));
const clear=fixture.alerts.filter(a=>a.rule.level>=10);
const review=fixture.alerts.filter(a=>a.rule.level>=5&&a.rule.level<10);
const normal=fixture.alerts.filter(a=>a.rule.level<5);
const source=readFileSync(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
test('실습 경보의 명확한 공격·확인 필요·정상 이벤트를 내용으로 구분한다',()=>{
  for(const [rows,action] of [[clear,'block'],[review,'alert'],[normal,'record']]){
    for(const alert of rows){const d=decide(alert);assert.equal(d.action,action,alert.rule.description);
      assert.deepEqual(Object.keys(d).sort(),['action','confidence','reason']);
      assert.ok(d.confidence>=0&&d.confidence<=1);assert.ok(!/[\r\n]/.test(d.reason));
      assert.equal(d.action,d.confidence>=0.85?'block':d.confidence>=0.5?'alert':'record');}
  }
  assert.equal(normal.filter(a=>decide(a).action==='block').length,0);
});
test('경보 30건은 30줄로 읽고 비밀값 형태를 가린다',()=>{
  assert.equal(formatAlertRows(extractAlertRows(fixture)).length,fixture.alerts.length);
  const copy=structuredClone(fixture);copy.alerts[0].rule.description='password=synthetic-private-value';
  assert.ok(!formatAlertRows(extractAlertRows(copy))[0].includes('synthetic-private-value'));
});
test('내장 패턴은 JSON과 일치하며 외부 의존 없이 ID·계정·주소·순서 변경에도 동작한다',()=>{
  assert.doesNotMatch(source,/\bimport\s*(?:\(|[{'"*])|\brequire\s*\(|\bfetch\s*\(|\bprocess\.|readFile|writeFile/);
  const local=runInNewContext(source.replace('export function decide','function decide')+'; ({decide,PATTERNS})',{});
  const patterns=JSON.parse(readFileSync(new URL('../xdr/exfiltration/patterns.json',import.meta.url))).patterns;
  assert.deepEqual(JSON.parse(JSON.stringify(local.PATTERNS)),patterns);
  for(const [i,alert] of [...fixture.alerts].reverse().entries()){
    const copy=structuredClone(alert);copy.id='changed-'+i;copy.data.srcuser='different-'+i;copy.data.srcip='192.0.2.234';
    if(copy.data.dstip)copy.data.dstip='2001:db8::1';
    copy.rule.mitre={id:copy.rule.mitre.map(t=>t.toLowerCase())};
    assert.equal(local.decide(copy).action,decide(alert).action);
  }
});
test('대량이라는 값 하나만으로 차단하지 않고 전송 전·실패·0바이트는 알림으로 둔다',()=>{
  const event=structuredClone(clear[0]);event.data.files='1';event.data.bytes='50000000';
  assert.equal(decide(event).action,'block');
  event.data.bytes='49999999';assert.equal(decide(event).action,'alert');
  event.data.bytes='90000000';event.rule.description='처음 보는 목적지로 전송 예정입니다.';
  assert.equal(decide(event).action,'alert');
  event.rule.description='처음 보는 목적지로 대량 전송이 실패했습니다.';assert.equal(decide(event).action,'alert');
  event.rule.description=clear[0].rule.description;event.data.bytes='0';event.data.files='200';
  assert.equal(decide(event).action,'alert');
  event.data.bytes='Infinity';event.data.files='-1';assert.equal(decide(event).action,'alert');
  assert.equal(decide(null).action,'record');
  assert.equal(decide({...event,rule:{level:12,mitre:['T1048'],description:'확인할 행위 정보가 없습니다.'}}).action,'record');
  assert.equal(decide(normal.find(a=>a.rule.mitre.includes('T1048'))).action,'record');
});
test('목적지 차단은 출발 IP나 계정을 넓게 막지 않고 만료 후 해제한다',async()=>{
  const now=new Date('2026-10-16T00:00:00Z');const plan=await buildResponsePlan(fixture.alerts,{now});
  assert.deepEqual(plan.counts,{block:10,alert:10,record:10});assert.equal(plan.denyCandidates.length,10);assert.equal(plan.alertEntries.length,10);
  for(const row of normal)assert.equal(createDenyCandidate(row,decide(row),now),null);
  for(const row of normal)assert.equal(activeDestinationDenials(row.data.dstip,plan.denyCandidates,now).length,0);
  assert.ok(activeDestinationDenials(clear[0].data.dstip,plan.denyCandidates,now).length>0);
  assert.equal(activeDestinationDenials(clear[0].data.srcip,plan.denyCandidates,now).length,0);
  assert.equal(activeDestinationDenials(clear[0].data.dstip,plan.denyCandidates,new Date(now.getTime()+1800000)).length,0);
  const addresses=[];
  const result=await applyDestinationBlocks(plan,{now,blockDestination:async ip=>addresses.push(ip)});
  assert.equal(result.blockedDestinations,new Set(clear.map(a=>a.data.dstip)).size);
  assert.equal(addresses.length,new Set(addresses).size);
  const missing=structuredClone(clear[0]);delete missing.data.dstip;
  assert.equal(createDenyCandidate(missing,decide(clear[0]),now),null);
});
test('응답 실행은 기존 로그를 보존하고 같은 경보를 다시 처리해도 중복이 없다',async()=>{
  const root=await mkdtemp(join(tmpdir(),'aleph-exfil-'));
  try{
    await mkdir(join(root,'xdr/fixtures'),{recursive:true});await mkdir(join(root,'xdr/exfiltration'));
    await writeFile(join(root,'xdr/fixtures/exfiltration.json'),JSON.stringify(fixture));
    await writeFile(join(root,'xdr/alerts.log'),'existing audit history\n');
    const now=new Date('2026-10-16T00:00:00Z');const first=await processFixture({root,now});const second=await processFixture({root,now});
    assert.equal(first.addedCandidates,10);assert.equal(first.loggedAlerts,10);
    assert.equal(second.addedCandidates,0);assert.equal(second.loggedAlerts,0);
    assert.ok((await readFile(join(root,'xdr/alerts.log'),'utf8')).startsWith('existing audit history\n'));
    const rules=JSON.parse(await readFile(join(root,'xdr/exfiltration/deny-rules.json'),'utf8')).rules;
    assert.equal(rules.length,10);
  }finally{await rm(root,{recursive:true,force:true});}
});
