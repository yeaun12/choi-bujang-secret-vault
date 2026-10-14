import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { verifyAssertion, verifyRegistration } from '../src/stage11-webauthn.mjs';
import { protectedPath, requireDeviceProof, sha256 } from '../src/stage11-device-proof.mjs';

const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const host='choi-bujang-secret-vault-blush.vercel.app';
const origin='https://'+host;
const b64=bytes=>Buffer.from(bytes).toString('base64url');
const digest=value=>createHash('sha256').update(value).digest();
const userId='123e4567-e89b-42d3-a456-426614174000';
const credId=b64(Buffer.alloc(32,42));

test('manifest / PWA shell have no protected cache or stored keys',()=>{
  const manifest=JSON.parse(read('public/manifest.webmanifest'));
  const page=read('public/index.html'),sw=read('public/sw.js'),off=read('public/offline.html');
  assert.equal(manifest.display,'standalone');
  assert.equal(manifest.start_url,'/');
  assert.match(page,/rel="manifest"/u);
  assert.match(page,/navigator\.credentials\.create/u);
  assert.match(page,/navigator\.credentials\.get/u);
  assert.match(page,/기기 서명으로 자료실 열기/u);
  assert.match(page,/오프라인에서는 개인 자료를 표시하지 않습니다/u);
  assert.doesNotMatch(page,/localStorage|sessionStorage|indexedDB/u);
  assert.doesNotMatch(sw,/caches\.open\([^)]*\)\.then\([^)]*cache\.put\(request/u);
  assert.match(sw,/request\.mode !== 'navigate'/u);
  assert.match(off,/서버 연결이 필요합니다/u);
});

function signedFixture(body='{"title":"ok","body":"safe"}',path='/api/notes/'+userId) {
  const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});
  const publicJwk=publicKey.export({format:'jwk'});
  const challenge=b64(Buffer.alloc(32,91));
  const client=b64(JSON.stringify({type:'webauthn.get',challenge,origin,crossOrigin:false}));
  const auth=Buffer.concat([digest(host),Buffer.from([0x05]),Buffer.alloc(4)]);
  const sig=sign('sha256',Buffer.concat([auth,digest(Buffer.from(client,'base64url'))]),privateKey);
  const registered={credential_id:credId,public_key_jwk:publicJwk,sign_count:0,revoked_at:null};
  const challengeId='123e4567-e89b-42d3-a456-426614174002';
  function request(changedBody=body,changedPath=path) {
    return new Request(origin+changedPath,{method:'PUT',body:changedBody,headers:{
      'X-Device-Challenge-Id':challengeId,'X-Device-Credential-Id':credId,
      'X-Device-Authenticator-Data':b64(auth),'X-Device-Client-Data':client,
      'X-Device-Signature':b64(sig),
    }});
  }
  function fakeDb(method='PUT',actualPath=path,actualBody=body) {
    let consumed=false;
    return {
      from(table) {
        let phase='', values={},filters={};
        const q={
          update(v){phase='update';values=v;return q},
          select(){return q},
          eq(k,v){filters[k]=v;return q},
          is(){return q},gt(){return q},
          async maybeSingle(){
            if(table==='stage11_device_challenges'){
              if(consumed||filters.id!==challengeId||filters.owner_id!==userId)
                return {data:null,error:null};
              consumed=true;
              return {data:{challenge,request_method:method,request_path:actualPath,
                body_sha256:sha256(Buffer.from(actualBody))},error:null};
            }
            if(table==='stage11_device_credentials'){
              return {data:filters.credential_id===credId ? registered:null,error:null};
            }
            return {data:null,error:{message:'bad_table'}};
          },
        };
        return q;
      },
    };
  }
  return {body,path,request,registered,challenge,client,auth,sig,fakeDb};
}

test('valid registered authenticator proof allows exactly the signed request once',async()=>{
  const f=signedFixture();
  const db=f.fakeDb();
  assert.equal(await requireDeviceProof(f.request(),{kind:'student',userId},db),null);
  const replay=await requireDeviceProof(f.request(),{kind:'student',userId},db);
  assert.equal(replay.status,403);
});

test('unsigned, changed body and changed path fail closed',async()=>{
  const f=signedFixture();
  const noProof=new Request(origin+f.path,{method:'PUT',body:f.body});
  const identity={kind:'student',userId};
  assert.equal((await requireDeviceProof(noProof,identity,f.fakeDb())).status,403);
  assert.equal((await requireDeviceProof(f.request('{"title":"evil","body":"safe"}'),identity,f.fakeDb())).status,403);
  const other='/api/notes/123e4567-e89b-42d3-a456-426614174003';
  assert.equal((await requireDeviceProof(f.request(f.body,other),identity,f.fakeDb())).status,403);
  assert.equal((await requireDeviceProof(f.request(),identity,f.fakeDb('POST'))).status,403);
});

test('invalid authenticator origin or signature and unregistered key denied',()=>{
  const f=signedFixture();
  assert.throws(()=>verifyAssertion({credentialId:credId,clientDataJSON:f.client,
    authenticatorData:b64(f.auth),signature:b64(Buffer.alloc(71,9)),challenge:f.challenge,
    rpId:host,origin,registered:f.registered}),/invalid_device_signature/u);
  assert.throws(()=>verifyAssertion({credentialId:credId,clientDataJSON:f.client,
    authenticatorData:b64(f.auth),signature:b64(f.sig),challenge:f.challenge,
    rpId:host,origin:'https://untrusted.example.com',registered:f.registered}),/client_data_mismatch/u);
  assert.throws(()=>verifyAssertion({credentialId:credId,clientDataJSON:f.client,
    authenticatorData:b64(f.auth),signature:b64(f.sig),challenge:f.challenge,
    rpId:host,origin,registered:null}),/device_not_registered/u);
});

test('protected-path allowlist never includes arbitrary routes or query tampering',()=>{
  assert.equal(protectedPath('PUT','/api/notes/'+userId),true);
  assert.equal(protectedPath('GET','/api/notes'),true);
  assert.equal(protectedPath('POST','/api/restore'),false);
  assert.equal(protectedPath('PUT','/api/notes/'+userId+'?body=evil'),false);
  assert.equal(protectedPath('PUT','/api/notes/'+userId+'/extra'),false);
  assert.equal(protectedPath('DELETE','/api/instructor-notices'),false);
});

test('stage 11 controls remain in deployments of stage 11 or later', async()=>{
  const config=JSON.parse(read('aleph.config.json'));
  const { deploymentIdentity }=await import('../scripts/deployment-identity.mjs');
  const out=deploymentIdentity({VERCEL_GIT_PROVIDER:'github',VERCEL_GIT_REPO_OWNER:'yeaun12',
    VERCEL_GIT_REPO_SLUG:'choi-bujang-secret-vault',
    VERCEL_GIT_COMMIT_SHA:'a'.repeat(40),VERCEL_URL:'choi-bujang-secret-vault-test-yeaun.vercel.app'},config);
  assert.equal(out.step,config.step);
  assert.ok(out.step >= 11);
  assert.equal(out.restoreRoute,'/api/restore');
  for(const route of ['GET /api/device','POST /api/device',
    'POST /api/device/challenge','POST /api/restore'])assert.ok(out.allowedRoutes.includes(route));
});
