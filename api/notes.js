import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  try {
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
    const { data, error } = await supabase
      .from('training_notes')
      .select('title,content')
      .order('id', { ascending: true });
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    return response.status(200).json({ notes: data ?? [] });
  } catch {
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
