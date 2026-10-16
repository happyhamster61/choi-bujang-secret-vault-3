import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { runAttackChecks } from '../src/attack-check.mjs';
const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
import { RULE_IDS } from '../src/decider.mjs';
import { NotesAccessError, requireNotesAccess, sendNotesError } from '../src/notes-service.mjs';
import { requireApprovedDevice } from '../src/device-proof.mjs';
import { sanitizeCheck, summarizeChecks, buildEvidenceGroups
} from '../src/operations-report.mjs';

async function countRows(supabase, table, ownerId = null) {
  try {
    let query = supabase.from(table).select('*', { head: true, count: 'exact' });
    if (ownerId) query = query.eq('owner_id', ownerId);
    const { count, error } = await query;
    if (error || !Number.isInteger(count)) return { status: 'unavailable', count: null };
    return { status: 'observed', count };
  } catch { return { status: 'unavailable', count: null }; }
}
async function backupVersion(supabase, ownerId) {
  try {
    const { data, error } = await supabase.from('stage10_note_backups')
      .select('baseline_commit,verified_at').eq('owner_id', ownerId).limit(1);
    if (error) return { status: 'unavailable', commit: null, verifiedAt: null };
    if (!Array.isArray(data) || !data.length) {
      return { status: 'not_applicable', commit: null, verifiedAt: null };
    }
    const item = data[0];
    return { status: 'observed', commit: item.baseline_commit,
      verifiedAt: item.verified_at };
  } catch { return { status: 'unavailable', commit: null, verifiedAt: null }; }
}
async function probeAnonymousNotes(origin) {
  const requestId = randomUUID();
  const checkedAt = new Date().toISOString();
  try {
    const response = await fetch(new URL('/api/notes', origin), {
      method: 'GET', cache: 'no-store', redirect: 'error',
      signal: AbortSignal.timeout(6000),
    });
    let errorCode = '';
    try {
      const data = await response.json();
      if (typeof data?.error === 'string' && /^[A-Z][A-Z0-9_]{0,59}$/.test(data.error)) errorCode = data.error;
    } catch { /* Do not copy response body */ }
    return sanitizeCheck({
      id: 'api-anonymous-notes', name: '무인증 메모 목록 GET',
      expected: 'HTTP 401 LOGIN_REQUIRED',
      observed: 'HTTP ' + response.status + (errorCode ? ' ' + errorCode : ''),
      requestId, checkedAt, status: 'observed', source: 'live_http_response'
    });
  } catch {
    return sanitizeCheck({
      id: 'api-anonymous-notes', name: '무인증 메모 목록 GET',
      expected: 'HTTP 401 LOGIN_REQUIRED', observed: null,
      requestId, checkedAt, status: 'unavailable',
      source: 'live_http_request_failed'
    });
  }
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const { supabase, userId } = await requireNotesAccess(request.headers?.authorization);
    await requireApprovedDevice(request, userId, supabase);
    const [deviceApproved, devicePending, deviceRevoked, restorus, version, probe] =
      await Promise.all([
        supabase.from('stage11_devices').select('*', { head:true, count:'exact' })
          .eq('owner_id',userId).eq('status','approved'),
        supabase.from('stage11_devices').select('*', { head:true, count:'exact' })
          .eq('owner_id',userId).eq('status','pending'),
        supabase.from('stage11_devices').select('*', { head:true, count:'exact' })
          .eq('owner_id',userId).eq('status','revoked'),
        countRows(supabase, 'stage10_restore_audit', userId),
        backupVersion(supabase, userId),
        probeAnonymousNotes(process.env.PUBLIC_APP_ORIGIN
          || 'https://choi-bujang-secret-vault-3-8kqo.vercel.app'),
      ]);
    const tally = row => row?.error || !Number.isInteger(row?.count)
      ? { status: 'unavailable', count: null }
      : { status: 'observed', count: row.count };
    const deploymentCommit = process.env.VERCEL_GIT_COMMIT_SHA ?? null;
    const groups = buildEvidenceGroups({probe,
      submissionAttempts:await runAttackChecks(config), deploymentCommit});
    const checks = Object.values(groups).flatMap(group => group.checks);
    return response.status(200).json({
      schema:'byteback.operations.v1',
      checkedAt:new Date().toISOString(),
      deploymentCommit,
      policy: { status:'source_verified', ruleIds:[...RULE_IDS],
        ruleCount:RULE_IDS.length, source:'src/decider.mjs',
        actualEngineDecisions:{status:'not_connected',count:null} },
      detection: { rule:'burst_read', threshold:121, windowMinutes:10,
        configured:true, events:{status:'not_connected',count:null},
        proposals:{status:'not_connected',count:null} },
      revocation: { status:'not_connected', executedCount:null },
      devices: { approved:tally(deviceApproved), pending:tally(devicePending),
        revoked:tally(deviceRevoked) },
      recovery: { backup:version, ownRestoreAudit:restorus },
      evidence: { summary:summarizeChecks(checks), checks, groups },
      note:'실제 HTTP 응답과 DB 카운트만 관측치입니다. 공식 41종은 미실행으로 남겨둡니다.'
    });
  } catch (error) {
    if (error instanceof NotesAccessError) return sendNotesError(response,error);
    return sendNotesError(response,error);
  }
}
