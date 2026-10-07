import { randomUUID } from 'node:crypto';
import { NotesAccessError, readJsonBody, requireNotesAccess, sendNotesError,
  toApiNote, validNoteFields } from '../src/notes-service.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  try {
    const { supabase, userId } = await requireNotesAccess(request.headers.authorization);
    if (request.method === 'GET') {
      const { data, error } = await supabase
        .from('training_notes')
        .select('note_uuid,title,content')
        .eq('owner_id', userId)
        .order('id', { ascending: true });
      if (error) throw error;
      return response.status(200).json((data ?? []).map(toApiNote));
    }

    const body = readJsonBody(request);
    if (!validNoteFields(body)) {
      return response.status(400).json({ error: 'INVALID_NOTE' });
    }
    const id = body.id === undefined ? randomUUID() : body.id;
    if (typeof id !== 'string' || !UUID.test(id)) {
      return response.status(400).json({ error: 'INVALID_NOTE_ID' });
    }

    const { error } = await supabase.from('training_notes').insert({
      note_uuid: id,
      owner_id: userId,
      title: body.title,
      content: body.body,
    });
    if (error) throw error;
    return response.status(201).json({ id });
  } catch (error) {
    if (error instanceof NotesAccessError) return sendNotesError(response, error);
    return sendNotesError(response, error);
  }
}
