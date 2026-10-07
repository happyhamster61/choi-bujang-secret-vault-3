import { createClient } from '@supabase/supabase-js';
import { createRequire } from 'node:module';
import { createLoginVerifier } from './verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let runtime;

export class NotesAccessError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function getRuntime(url, secretKey) {
  if (runtime) return runtime;

  const restPath = new URL('rest/v1/', url).pathname;
  const fetchWithoutSecretBearer = (input, init = {}) => {
    const requestUrl = new URL(input instanceof Request ? input.url : input);
    if (secretKey.startsWith('sb_secret_')
        && requestUrl.origin === new URL(url).origin
        && requestUrl.pathname.startsWith(restPath)) {
      const headers = new Headers(init.headers);
      headers.delete('Authorization');
      return fetch(input, { ...init, headers });
    }
    return fetch(input, init);
  };
  const supabase = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    global: { fetch: fetchWithoutSecretBearer },
  });
  const verifyLogin = createLoginVerifier({ config, supabaseClient: supabase });
  runtime = { supabase, verifyLogin };
  return runtime;
}

export async function requireNotesAccess(authorization) {
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    throw new NotesAccessError(401, 'LOGIN_REQUIRED');
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) throw new NotesAccessError(503, 'NOTES_UNAVAILABLE');

  let identity;
  let supabase;
  try {
    const context = getRuntime(url, secretKey);
    supabase = context.supabase;
    identity = await context.verifyLogin(authorization);
  } catch {
    throw new NotesAccessError(502, 'NOTES_UNAVAILABLE');
  }

  if (!identity || identity.kind !== 'student' || !UUID.test(identity.userId ?? '')) {
    throw new NotesAccessError(401, 'LOGIN_REQUIRED');
  }
  return { supabase, userId: identity.userId };
}

export function sendNotesError(response, error) {
  if (error instanceof NotesAccessError) {
    return response.status(error.status).json({ error: error.code });
  }
  return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
}

export function readJsonBody(request) {
  if (request.body && typeof request.body === 'object') return request.body;
  if (typeof request.body === 'string') {
    try { return JSON.parse(request.body); } catch { return null; }
  }
  return null;
}

export function validNoteFields(body) {
  return body && typeof body.title === 'string' && body.title.trim().length > 0
    && typeof body.body === 'string';
}

export function toApiNote(row) {
  return { id: row.note_uuid, title: row.title, body: row.content };
}
