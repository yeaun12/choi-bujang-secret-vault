import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { verifyRegistration } from '../../src/stage11-webauthn.mjs';
import { consumeDeviceChallenge, credentialsFor, issueDeviceChallenge, origin, rpId } from '../../src/stage11-device-proof.mjs';

let db, verifyLogin;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) throw Error('missing_configuration');
  db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: { persistSession: false, autoRefreshToken: false } });
  verifyLogin = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
} catch { db = null; verifyLogin = null; }
const json = (x, status=200) => Response.json(x, {status,headers:{'Cache-Control':'no-store'}});
async function authorize(request) {
  if (!db || !verifyLogin) return { response: json({error:'Device service unavailable.'},503) };
  const identity = await verifyLogin(request.headers.get('authorization'));
  if (identity?.kind !== 'student') return { response:json({error:'Student login required.'},401) };
  return {identity};
}
export async function GET(request) {
  const a=await authorize(request); if(a.response)return a.response;
  try {
    const credentials=await credentialsFor(db,a.identity);
    return json({registered:credentials.length>0,
      credentials:credentials.map(x=>({id:x.credential_id, type:'public-key'})),
      verifiedForThisRequest:false});
  } catch {return json({error:'Device status unavailable.'},503);}
}
export async function POST(request) {
  const a=await authorize(request); if(a.response)return a.response;
  let body;try{body=await request.json();}catch{return json({error:'Invalid JSON.'},400)}
  if (!body || typeof body!=='object' || Array.isArray(body))return json({error:'Invalid request.'},400);
  if(body.action==='begin') {
    try {
      const {challengeId, challenge}=await issueDeviceChallenge(db,a.identity,{kind:'register'});
      const credentials=await credentialsFor(db,a.identity);
      return json({challengeId, publicKey:{
        challenge,
        rp:{name:'BYTE BACK 안전 접속',id:rpId},
        user:{id:Buffer.from(a.identity.userId).toString('base64url'),
          name:'BYTE BACK 계정',displayName:'BYTE BACK 기기'},
        pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{
          residentKey:'preferred',userVerification:'required'},
        attestation:'none',timeout:90000,
        excludeCredentials:credentials.map(x=>({type:'public-key',id:x.credential_id})),
      }});
    } catch {return json({error:'Registration challenge unavailable.'},503);}
  }
  if(body.action==='finish') {
    const registration=body.credential;
    if (!registration || typeof registration!=='object' ||
        typeof registration.id!=='string' || registration.type!=='public-key' ||
        typeof registration.clientDataJSON!=='string' || typeof registration.attestationObject!=='string') {
      return json({error:'Invalid credential.'},400);
    }
    try {
      const ch=await consumeDeviceChallenge(db,a.identity,body.challengeId,'register');
      const verified=verifyRegistration({attestationObject:registration.attestationObject,
        clientDataJSON:registration.clientDataJSON,challenge:ch.challenge,
        rpId,origin,credentialId:registration.id});
      const {data,error}=await db.from('stage11_device_credentials')
        .insert({owner_id:a.identity.userId,credential_id:verified.credentialId,
          public_key_jwk:verified.publicJwk,sign_count:verified.counter})
        .select('credential_id').single();
      if (error || !data) return json({error:'Device registration could not be saved.'},503);
      return json({registered:true,approved:true,credentialId:data.credential_id},201);
    } catch {return json({error:'Device registration could not be verified.'},403);}
  }
  return json({error:'Unknown action.'},400);
}
export async function PUT(){return json({error:'Method not allowed.'},405)}
export async function DELETE(){return json({error:'Method not allowed.'},405)}
