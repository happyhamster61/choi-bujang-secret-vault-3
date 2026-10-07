import { createClient } from '@supabase/supabase-js';
import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
let supabase;
let verifyLogin;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  try {
    if (!supabase || !verifyLogin) {
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
      supabase = createClient(url, secretKey, {
        auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
        global: { fetch: fetchWithoutSecretBearer },
      });
      verifyLogin = createLoginVerifier({ config, supabaseClient: supabase });
    }

    const identity = await verifyLogin(authorization);
    if (!identity || identity.kind !== 'student') {
      return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }

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
