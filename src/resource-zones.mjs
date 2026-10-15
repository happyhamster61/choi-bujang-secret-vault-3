import { NotesAccessError, requireNotesAccess } from './notes-service.mjs';

// Resource IDs are distinct from URL routes. Scope and role come from stored
// server-side rows, never from the request body, query, or browser headers.
export const RESOURCE_ZONES = Object.freeze({
  NOTE: 'note',
  CLASS_ANNOUNCEMENT: 'class_announcement',
  INSTRUCTOR_MATERIAL: 'instructor_material',
});
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function resourceIdFromRoute(request) {
  // Vercel route params must refer to a single segment; never select a zone
  // or an operation via query strings.
  const requestUrl = new URL(request.url, 'https://localhost');
  const pathname = requestUrl.pathname;
  const segments = pathname.split('/');
  if (segments.some(part => part === '.' || part === '..') || pathname.includes('%')) {
    throw new NotesAccessError(400, 'INVALID_RESOURCE_ID');
  }
  const id = segments.at(-1);
  if (id !== request.query?.id && request.query?.id !== undefined) {
    throw new NotesAccessError(400, 'INVALID_RESOURCE_ID');
  }
  if (typeof id !== 'string' || !UUID.test(id)) {
    throw new NotesAccessError(400, 'INVALID_RESOURCE_ID');
  }
  return id;
}

export async function verifiedResourceUser(request) {
  return requireNotesAccess(request.headers?.authorization);
}

export async function resourceAndMembership(supabase, userId, id, zone) {
  const { data: resource, error } = await supabase.from('training_zone_resources')
    .select('resource_id,zone,class_id,title,content')
    .eq('resource_id', id).eq('zone', zone).maybeSingle();
  if (error) throw error;
  if (!resource) throw new NotesAccessError(404, 'RESOURCE_NOT_FOUND');
  const { data: membership, error: memberError } = await supabase
    .from('training_class_memberships').select('role')
    .eq('class_id', resource.class_id).eq('user_id', userId).maybeSingle();
  if (memberError) throw memberError;
  if (!membership) throw new NotesAccessError(404, 'RESOURCE_NOT_FOUND');
  return { resource, membership };
}
