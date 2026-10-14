import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { credentialsFor, issueDeviceChallenge } from '../../src/stage11-device-proof.mjs';

let db, verifyLogin;
try {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) throw Error('missing_configuration');
  db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY,
    { auth: {persistSession:false,autoRefreshToken:false} });
  verifyLogin = createLoginVerifier({config,supabaseSecretKey:process.env.SUPABASE_SECRET_KEY});
} catch {db=null;verifyLogin=null;}
const json = (data,status=200) => Response.json(data,{status,headers:{'Cache-Control':'no-store'}});
export async function POST(request) {
  if(!db||!verifyLogin)return json({error:'Device service unavailable.'},503);
  const identity=await verifyLogin(request.headers.get('authorization'));
  if(identity?.kind!=='student')return json({error:'Student login required.'},401);
  let body;try{body=await request.json()}catch{return json({error:'Invalid JSON.'},400)}
  if (!body||typeof body!=='object'||Array.isArray(body))return json({error:'Invalid request.'},400);
  try {
    const credentials=await credentialsFor(db,identity);
    if(credentials.length===0)return json({error:'No registered device.'},403);
    const issued=await issueDeviceChallenge(db,identity,{
      kind:'request',method:body.method,path:body.path,bodyHash:body.bodySha256});
    return json({...issued,rpId:new URL(config.publicAppUrl).hostname,
      allowCredentials:credentials.map(x=>({type:'public-key',id:x.credential_id}))});
  } catch {return json({error:'Invalid challenge request or storage unavailable.'},400);}
}
export async function GET(){return json({error:'Method not allowed.'},405)}
export async function PUT(){return json({error:'Method not allowed.'},405)}
export async function DELETE(){return json({error:'Method not allowed.'},405)}
