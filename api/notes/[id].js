import { NotesAccessError, readJsonBody, requireNotesAccess, sendNotesError,
  toApiNote, validNoteFields } from '../../src/notes-service.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function noteIdFromRequest(request) {
  const routeId = request.query?.id;
  if (typeof routeId === 'string') return routeId;
  const pathname = new URL(request.url, `https://${request.headers.host || 'localhost'}`).pathname;
  return decodeURIComponent(pathname.slice(pathname.lastIndexOf('/') + 1));
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  let id;
  try { id = noteIdFromRequest(request); } catch {
    return response.status(400).json({ error: 'INVALID_NOTE_ID' });
  }
  if (!UUID.test(id)) return response.status(400).json({ error: 'INVALID_NOTE_ID' });

  try {
    const { supabase, userId } = await requireNotesAccess(request.headers.authorization);
    if (request.method === 'GET') {
      const { data, error } = await supabase.from('training_notes')
        .select('note_uuid,title,content,owner_id')
        .eq('note_uuid', id).eq('owner_id', userId).maybeSingle();
      if (error) throw error;
      if (!data || data.owner_id !== userId) {
        return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
      }
      return response.status(200).json(toApiNote(data));
    }

    if (request.method === 'PUT') {
      const body = readJsonBody(request);
      if (!validNoteFields(body) || Object.prototype.hasOwnProperty.call(body, 'owner_id')) {
        return response.status(400).json({ error: 'INVALID_NOTE' });
      }
      const { data, error } = await supabase.from('training_notes')
        .update({ title: body.title, content: body.body })
        .eq('note_uuid', id).eq('owner_id', userId)
        .select('note_uuid,title,content,owner_id')
        .maybeSingle();
      if (error) throw error;
      if (!data || data.owner_id !== userId) {
        return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
      }
      return response.status(200).json(toApiNote(data));
    }

    const { data, error } = await supabase.from('training_notes')
      .delete().eq('note_uuid', id).eq('owner_id', userId)
      .select('note_uuid,owner_id').maybeSingle();
    if (error) throw error;
    if (!data || data.owner_id !== userId) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }
    return response.status(204).end();
  } catch (error) {
    if (error instanceof NotesAccessError) return sendNotesError(response, error);
    return sendNotesError(response, error);
  }
}
