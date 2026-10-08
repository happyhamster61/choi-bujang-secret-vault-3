import { createClient } from '@supabase/supabase-js';

const ACCESS_COOKIE = '__Host-sb-access-token';
const REFRESH_COOKIE = '__Host-sb-refresh-token';
const COOKIE_ATTRIBUTES = '; HttpOnly; Secure; SameSite=Lax; Path=/';

function parseRequestBody(body) {
  if (body && typeof body === 'object' && !Array.isArray(body)) return body;
  if (typeof body !== 'string' || body.length === 0) return null;

  try {
    const parsed = JSON.parse(body);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const body = parseRequestBody(request.body);
  if (
    !body ||
    typeof body.email !== 'string' ||
    body.email.trim().length === 0 ||
    typeof body.password !== 'string' ||
    body.password.length === 0
  ) {
    return response.status(400).json({ error: 'INVALID_REQUEST' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!supabaseUrl || !publishableKey) {
    return response.status(503).json({ error: 'AUTH_UNAVAILABLE' });
  }

  try {
    const supabase = createClient(supabaseUrl, publishableKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false,
      },
    });

    const { data, error } = await supabase.auth.signInWithPassword({
      email: body.email.trim(),
      password: body.password,
    });

    if (error) {
      return response.status(401).json({ error: 'INVALID_CREDENTIALS' });
    }

    const session = data?.session;
    if (
      !session ||
      typeof session.access_token !== 'string' ||
      typeof session.refresh_token !== 'string'
    ) {
      return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
    }

    response.setHeader('Set-Cookie', [
      `${ACCESS_COOKIE}=${encodeURIComponent(session.access_token)}${COOKIE_ATTRIBUTES}`,
      `${REFRESH_COOKIE}=${encodeURIComponent(session.refresh_token)}${COOKIE_ATTRIBUTES}`,
    ]);

    return response.status(200).json({ authenticated: true });
  } catch {
    return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
  }
}
