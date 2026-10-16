import { createClient } from '@supabase/supabase-js';
import { createRequire } from 'node:module';
import { readJsonBody } from '../src/notes-service.mjs';
const config = createRequire(import.meta.url)('../aleph.config.json');

// Fresh client for each request: never share one user's auth state with another.
export function createAuthHandler({ env = process.env, clientFactory = createClient } = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    if (!['POST', 'DELETE'].includes(request.method)) {
      response.setHeader('Allow', 'POST, DELETE');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    const origin = request.headers?.origin;
    const host = request.headers?.host;
    if (origin && origin !== config.publicAppUrl && origin !== `https://${host}`) {
      return response.status(403).json({ error: 'ORIGIN_REJECTED' });
    }
    const url = env.SUPABASE_URL;
    const key = env.SUPABASE_SECRET_KEY;
    if (!url || !key) return response.status(503).json({ error: 'AUTH_UNAVAILABLE' });
    try {
      // The server-only key is never returned. No refresh token is sent to the UI.
      const client = clientFactory(url, key, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      if (request.method === 'DELETE') {
        const authorization = request.headers?.authorization;
        if (typeof authorization !== 'string' || !/^Bearer \S{1,8192}$/.test(authorization)) {
          return response.status(401).json({ error: 'LOGIN_REQUIRED' });
        }
        const { error } = await client.auth.admin.signOut(authorization.slice(7), 'local');
        if (error) return response.status(401).json({ error: 'LOGIN_REQUIRED' });
        return response.status(200).json({ signedOut: true });
      }
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers?.['content-type'] ?? '')) {
        return response.status(415).json({ error: 'JSON_REQUIRED' });
      }
      const body = readJsonBody(request);
      if (!body || typeof body.email !== 'string' || body.email.length > 254
          || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)
          || typeof body.password !== 'string' || !body.password.length
          || body.password.length > 4096
          || Object.keys(body).some(k => !['email', 'password'].includes(k))) {
        return response.status(400).json({ error: 'INVALID_LOGIN_INPUT' });
      }
      const { data, error } = await client.auth.signInWithPassword({
        email: body.email, password: body.password,
      });
      if (error) return response.status(error.status === 429 ? 429 : 401)
        .json({ error: error.status === 429 ? 'AUTH_RATE_LIMITED' : 'INVALID_CREDENTIALS' });
      const session = data?.session;
      if (!session?.access_token || !session.user?.id || !Number.isFinite(session.expires_at)) {
        return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
      }
      return response.status(200).json({ session: {
        access_token: session.access_token, expires_at: session.expires_at,
        user: { id: session.user.id },
      } });
    } catch {
      return response.status(502).json({ error: 'AUTH_UNAVAILABLE' });
    }
  };
}
export default createAuthHandler();
