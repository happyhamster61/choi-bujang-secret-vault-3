import { readFile, writeFile, appendFile, rename, rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { decide } from './decide.mjs';
const TTL_MS = 30 * 60 * 1000;
function safe(value) {
  return String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi,'[redacted]')
    .replace(/\bBearer\s+[^\s,;]+/gi,'Bearer [redacted]')
    .replace(/\b(password|passwd|token|secret|api[_ -]?key|cookie|credential)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;&]+)/gi,'[redacted]')
    .replace(/\bsb_(?:secret|publishable)_[A-Za-z0-9_-]+\b/g,'[redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,'[redacted]')
    .replace(/[\r\n]+/g,' ').trim();
}
export function normalizeDestination(address) {
  if (typeof address !== 'string') return null;
  const ip = address.trim();
  if (isIP(ip) === 4) return ip;
  if (isIP(ip) === 6) return new URL(`http://[${ip}]/`).hostname.slice(1,-1);
  return null;
}
function validDecision(d) {
  return d && typeof d.confidence === 'number' && Number.isFinite(d.confidence)
    && d.confidence >= 0 && d.confidence <= 1 && typeof d.reason === 'string'
    && d.action === (d.confidence >= 0.85 ? 'block' : d.confidence >= 0.5 ? 'alert' : 'record');
}
export function createDenyCandidate(alert, decision, now = new Date()) {
  if (!validDecision(decision) || decision.action !== 'block') return null;
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw TypeError('유효한 처리 시각이 필요합니다.');
  const destinationAddress = normalizeDestination(alert?.data?.dstip);
  const alertId = typeof alert?.id === 'string' ? safe(alert.id) : '';
  if (!destinationAddress || !alertId) return null;
  return { effect:'deny', scope:'destination', destinationAddress,
    alertId, expiresAt:new Date(now.getTime()+TTL_MS).toISOString(),
    reason:safe(decision.reason) };
}
export function activeDestinationDenials(destination, rules, now = new Date()) {
  const ip = normalizeDestination(destination);
  if (!ip || !Array.isArray(rules) || !(now instanceof Date) || !Number.isFinite(now.getTime())) return [];
  return rules.filter(r => r?.effect === 'deny' && r.scope === 'destination'
    && normalizeDestination(r.destinationAddress) === ip
    && typeof r.alertId === 'string' && r.alertId.length > 0
    && Number.isFinite(Date.parse(r.expiresAt)) && Date.parse(r.expiresAt) > now.getTime());
}
// The trusted policy/egress service supplies this callback. No API or network
// changes are made just by reading a fixture or importing the module.
export async function applyDestinationBlocks(plan, {blockDestination, now = new Date()} = {}) {
  if (typeof blockDestination !== 'function') throw TypeError('목적지 차단 콜백이 필요합니다.');
  const groups = new Map();
  for (const rule of plan.denyCandidates) {
    if (!activeDestinationDenials(rule.destinationAddress,[rule],now).length) continue;
    const group = groups.get(rule.destinationAddress) ?? [];
    group.push(rule); groups.set(rule.destinationAddress,group);
  }
  for (const [destination,rules] of groups) {
    await blockDestination(destination,{
      alertIds:[...new Set(rules.map(r=>r.alertId))],
      expiresAt:rules.map(r=>r.expiresAt).sort().at(-1),
    });
  }
  return {blockedDestinations:groups.size};
}
export async function buildResponsePlan(alerts, {now=new Date(),decideAlert=decide} = {}) {
  if (!Array.isArray(alerts)) throw TypeError('경보 배열이 필요합니다.');
  const counts={block:0,alert:0,record:0}, denyCandidates=[], alertEntries=[];
  for (const alert of alerts) {
    const d=await decideAlert(alert);
    if (!validDecision(d)) throw TypeError('판정 결과 형식 또는 확신도와 동작이 맞지 않습니다.');
    counts[d.action]++;
    const candidate=createDenyCandidate(alert,d,now);
    if (candidate) denyCandidates.push(candidate);
    if (d.action === 'alert') alertEntries.push({moduleKey:'exfiltration',
      alertId:safe(alert?.id),action:'alert',confidence:d.confidence,reason:safe(d.reason)});
  }
  return {counts,denyCandidates,alertEntries};
}
async function textOrEmpty(path) {
  try { return await readFile(path,'utf8'); }
  catch(e) { if(e.code==='ENOENT') return ''; throw e; }
}
export async function processFixture({root,now=new Date()}) {
  const fixture=JSON.parse(await readFile(resolve(root,'xdr/fixtures/exfiltration.json'),'utf8'));
  if(fixture.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='exfiltration') throw Error('경보 묶음 형식이 아닙니다.');
  const plan=await buildResponsePlan(fixture.alerts,{now});
  const rulePath=resolve(root,'xdr/exfiltration/deny-rules.json');
  const previous=await textOrEmpty(rulePath);
  const state=previous?JSON.parse(previous):{schema:'aleph.xdr.deny-candidates.v1',rules:[]};
  if(state.schema!=='aleph.xdr.deny-candidates.v1'||!Array.isArray(state.rules)) throw Error('기존 후보 형식 오류: 보존을 위해 중단합니다.');
  const rules=[...state.rules]; let addedCandidates=0;
  for(const candidate of plan.denyCandidates) {
    const index=rules.findIndex(r=>r.alertId===candidate.alertId&&r.destinationAddress===candidate.destinationAddress);
    if(index<0){rules.push(candidate);addedCandidates++;}
    else if(Date.parse(rules[index].expiresAt)<=now.getTime()) rules[index]=candidate;
  }
  const temp=rulePath+'.'+process.pid+'.tmp';
  try {await writeFile(temp,JSON.stringify({...state,rules},null,2)+'\n');await rename(temp,rulePath);}
  finally {await rm(temp,{force:true});}
  const logPath=resolve(root,'xdr/alerts.log');
  const log=await textOrEmpty(logPath);const known=new Set();
  for(const line of log.split(/\r?\n/)){
    try{const r=JSON.parse(line);if(r.action==='alert'&&r.moduleKey==='exfiltration')known.add(r.alertId);}catch{}
  }
  const additions=plan.alertEntries.filter(r=>!known.has(r.alertId));
  if(additions.length)await appendFile(logPath,(log&&!log.endsWith('\n')?'\n':'')+
    additions.map(r=>JSON.stringify(r)).join('\n')+'\n');
  return {...plan,addedCandidates,loggedAlerts:additions.length};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try {
    const plan=await processFixture({root:fileURLToPath(new URL('../../',import.meta.url))});
    console.log(JSON.stringify({counts:plan.counts,denyCandidates:plan.denyCandidates.length,
      addedCandidates:plan.addedCandidates,loggedAlerts:plan.loggedAlerts}));
    console.log('목적지 차단 후보를 기록했으며 실제 운영 차단은 실행하지 않았습니다.');
  }catch(e){console.error('응답 처리 실패: '+e.message);process.exitCode=1;}
}
