import { requireApprovedDevice } from '../../../src/device-proof.mjs';
import { sendNotesError, readJsonBody, validNoteFields,
  NotesAccessError } from '../../../src/notes-service.mjs';
import { RESOURCE_ZONES, resourceAndMembership, resourceIdFromRoute,
  verifiedResourceUser } from '../../../src/resource-zones.mjs';

// Management-only API, outside the student policy's allowedRoutes.
// Authorization is a server-side membership lookup, not a client role.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'PUT') {
    response.setHeader('Allow', 'PUT');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const id = resourceIdFromRoute(request);
    const { supabase, userId } = await verifiedResourceUser(request);
    await requireApprovedDevice(request, userId, supabase);
    const { resource, membership } = await resourceAndMembership(supabase, userId, id,
      RESOURCE_ZONES.CLASS_ANNOUNCEMENT);
    if (membership.role !== 'instructor') {
      throw new NotesAccessError(403, 'ROLE_REQUIRED');
    }
    const body = readJsonBody(request);
    if (!validNoteFields(body) || Object.hasOwn(body, 'role')
        || Object.hasOwn(body, 'owner_id') || Object.hasOwn(body, 'zone')
        || Object.hasOwn(body, 'class_id')) {
      throw new NotesAccessError(400, 'INVALID_NOTE');
    }
    const { data, error } = await supabase.from('training_zone_resources')
      .update({ title: body.title, content: body.body })
      .eq('resource_id', resource.resource_id)
      .eq('zone', RESOURCE_ZONES.CLASS_ANNOUNCEMENT)
      .eq('class_id', resource.class_id)
      .select('resource_id,zone,title,content').maybeSingle();
    if (error) throw error;
    if (!data) throw new NotesAccessError(404, 'RESOURCE_NOT_FOUND');
    return response.status(200).json({
      id: data.resource_id, zone: data.zone, title: data.title, body: data.content,
    });
  } catch (error) {
    return sendNotesError(response, error);
  }
}
