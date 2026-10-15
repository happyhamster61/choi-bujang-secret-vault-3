import { sendNotesError, NotesAccessError } from '../../src/notes-service.mjs';
import { resourceIdFromRoute, verifiedResourceUser } from '../../src/resource-zones.mjs';

// Instructor materials are outside the student-facing resource zone.
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  try {
    resourceIdFromRoute(request);
    await verifiedResourceUser(request);
    throw new NotesAccessError(403, 'ZONE_DENIED');
  } catch (error) {
    return sendNotesError(response, error);
  }
}
