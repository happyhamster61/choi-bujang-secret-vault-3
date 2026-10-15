import { NotesAccessError, sendNotesError } from '../../src/notes-service.mjs';
import { RESOURCE_ZONES, resourceAndMembership, resourceIdFromRoute,
  verifiedResourceUser } from '../../src/resource-zones.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const id = resourceIdFromRoute(request);
    const { supabase, userId } = await verifiedResourceUser(request);
    const { resource } = await resourceAndMembership(supabase, userId, id,
      RESOURCE_ZONES.CLASS_ANNOUNCEMENT);
    return response.status(200).json({
      id: resource.resource_id, zone: resource.zone,
      title: resource.title, body: resource.content,
    });
  } catch (error) {
    return sendNotesError(response, error);
  }
}
