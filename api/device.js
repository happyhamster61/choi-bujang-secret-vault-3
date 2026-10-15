import { randomUUID } from 'node:crypto';
import { NotesAccessError, requireNotesAccess, sendNotesError,
  readJsonBody } from '../src/notes-service.mjs';
import { validPublicDeviceKey, verifyDeviceProof } from '../src/device-proof.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export default async function handler(request, response) {
  response.setHeader('Cache-Control','no-store');
  if (!['POST','GET'].includes(request.method)) {
    response.setHeader('Allow','GET, POST');
    return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
  }
  try {
    const { supabase,userId } = await requireNotesAccess(request.headers?.authorization);
    if (request.method === 'POST') {
      const body = readJsonBody(request);
      if (!body || !validPublicDeviceKey(body.publicJwk)
          || Object.keys(body).sort().join(',') !== 'publicJwk') {
        throw new NotesAccessError(400,'INVALID_DEVICE_REQUEST');
      }
      const deviceId = randomUUID();
      const { error } = await supabase.from('stage11_devices')
        .insert({ device_id:deviceId, owner_id:userId,
          public_jwk:body.publicJwk,status:'pending' });
      if (error) throw new NotesAccessError(503,'DEVICE_CHECK_UNAVAILABLE');
      return response.status(202).json({deviceId,status:'pending'});
    }

    // Status can reveal only the authenticated user's own device.
    const id = request.query?.id;
    if (typeof id !== 'string' || !UUID.test(id)) {
      throw new NotesAccessError(400,'INVALID_DEVICE_ID');
    }
    const { data,error } = await supabase.from('stage11_devices')
      .select('status,public_jwk').eq('owner_id',userId)
      .eq('device_id',id).maybeSingle();
    if (error) throw new NotesAccessError(503,'DEVICE_CHECK_UNAVAILABLE');
    if (!data) throw new NotesAccessError(404,'DEVICE_NOT_FOUND');
    // Do not disclose approved state without proof of the associated private key.
    const url = new URL(request.url,'https://localhost');
    const valid = verifyDeviceProof({
      method:'GET',path:url.pathname+url.search, body:null,
      time:request.headers?.['x-device-time'],
      nonce:request.headers?.['x-device-nonce'],
      signature:request.headers?.['x-device-signature'],
      publicJwk:data.public_jwk });
    if (!valid) throw new NotesAccessError(403,'DEVICE_PROOF_INVALID');
    return response.status(200).json({status:data.status,approved:data.status==='approved'});
  } catch(error) { return sendNotesError(response,error); }
}
