import { NotesAccessError, readJsonBody, requireVerifiedRestoreAccess,
  sendNotesError } from '../src/notes-service.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// Restore exactly one verified B fixture note. This endpoint neither accepts
// note contents/owners from clients nor modifies policy or historical audit.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  try {
    const { supabase, identity } = await requireVerifiedRestoreAccess(
      request.headers?.authorization);
    const body = readJsonBody(request) ?? {};
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some(key => !['id', 'noteId'].includes(key))
        || (body.id !== undefined && body.noteId !== undefined && body.id !== body.noteId)) {
      throw new NotesAccessError(400, 'INVALID_RESTORE_REQUEST');
    }
    const candidateId = body.id ?? body.noteId;
    if (candidateId !== undefined && (typeof candidateId !== 'string'
        || !UUID.test(candidateId))) {
      throw new NotesAccessError(400, 'INVALID_NOTE_ID');
    }

    // Backup is access-controlled and was verified BEFORE the challenge replay.
    // Never return its text or the private owner identifier to a caller.
    let query = supabase.from('stage10_note_backups')
      .select('note_uuid,owner_id,content_sha256,verified_at,baseline_commit');
    if (candidateId !== undefined) query = query.eq('note_uuid', candidateId);
    if (identity.kind === 'student') query = query.eq('owner_id', identity.userId);
    const { data: backups, error } = await query.limit(2);
    if (error) throw error;
    if (!Array.isArray(backups) || backups.length !== 1) {
      throw new NotesAccessError(404, 'VERIFIED_BACKUP_NOT_FOUND');
    }
    const backup = backups[0];
    if (identity.kind === 'judge' && identity.identity !== 'b') {
      throw new NotesAccessError(403, 'RESTORE_NOT_ALLOWED');
    }
    if (!UUID.test(backup.note_uuid) || !UUID.test(backup.owner_id)
        || backup.baseline_commit !== 'cbdbbed3bb5f2c97bb5efeb82c0d9e7ef750c27c'
        || !/^[a-f0-9]{64}$/u.test(backup.content_sha256)
        || typeof backup.verified_at !== 'string') {
      throw new NotesAccessError(409, 'BACKUP_NOT_VERIFIED');
    }
    const { data: restoredId, error: restoreError } = await supabase.rpc(
      'stage10_restore_verified_note',
      { p_note_uuid: backup.note_uuid, p_owner_id: backup.owner_id });
    if (restoreError || restoredId !== backup.note_uuid) {
      throw new NotesAccessError(409, 'RESTORE_FAILED');
    }
    return response.status(200).json({
      restored: true, id: restoredId, verified: true,
    });
  } catch (error) {
    return sendNotesError(response, error);
  }
}
