// Deployment gate: temporary synthetic user, no emails, no production note writes.
// Credentials and tokens stay in process memory and are never logged or saved.
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createAuthHandler } from '../api/auth.js';
import { requireNotesAccess } from '../src/notes-service.mjs';
import { requireApprovedDevice } from '../src/device-proof.mjs';

const { SUPABASE_URL: url, SUPABASE_SECRET_KEY: key } = process.env;
if (!url || !key) throw Error('Server login gate: missing server configuration');
const admin = createClient(url, key, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});
const email = `aleph-login-check-${randomUUID()}@example.com`;
const password = randomBytes(32).toString('base64url');
let userId;
function response() {
  return { statusCode: null, body: null, headers: {},
    setHeader(k,v) { this.headers[k] = v; },
    status(n) { this.statusCode = n; return this; },
    json(v) { this.body = v; return this; } };
}
try {
  const created = await admin.auth.admin.createUser({email,password,email_confirm:true});
  if (created.error || !created.data?.user?.id) throw Error('Server login gate: temporary user creation failed');
  userId = created.data.user.id;
  const handler = createAuthHandler();
  const login = response();
  await handler({method:'POST',headers:{'content-type':'application/json'},
    body:{email,password}}, login);
  assert.equal(login.statusCode,200,'Server login gate: password login failed');
  assert.equal(login.headers['Cache-Control'],'no-store');
  const session = login.body.session;
  assert.equal(session.user.id,userId);
  assert.equal('refresh_token' in session,false);
  const authorization = 'Bearer ' + session.access_token;
  const access = await requireNotesAccess(authorization);
  assert.equal(access.userId,userId,'Server login gate: existing API verifier rejected login');
  await assert.rejects(requireApprovedDevice({headers:{}},userId,access.supabase),
    {status:403,code:'DEVICE_APPROVAL_REQUIRED'});
  const invalid = response();
  await handler({method:'POST',headers:{'content-type':'application/json'},
    body:{email,password:randomBytes(32).toString('hex')}},invalid);
  assert.equal(invalid.statusCode,401);
  const logout = response();
  await handler({method:'DELETE',headers:{authorization}},logout);
  assert.equal(logout.statusCode,200,'Server login gate: logout failed');
  console.log('Server login gate: real password login, API identity, unapproved-device denial, invalid password and logout verified.');
} finally {
  if (userId) {
    const removed = await admin.auth.admin.deleteUser(userId);
    if (removed.error) throw Error('Server login gate: temporary user cleanup failed');
    console.log('Server login gate: temporary user removed; no notes or device approvals created.');
  }
}
