import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { verifyRegistration } from '../src/stage11-webauthn.mjs';

const host='choi-bujang-secret-vault-blush.vercel.app';
const origin='https://'+host;
const b64=v=>Buffer.from(v).toString('base64url');
const sha=v=>createHash('sha256').update(v).digest();
function head(type,len) {
  if(len<24)return Buffer.from([(type<<5)|len]);
  if(len<=255)return Buffer.from([(type<<5)|24,len]);
  const out=Buffer.alloc(3);out[0]=(type<<5)|25;out.writeUInt16BE(len,1);return out;
}
function encode(v) {
  if(typeof v==='number'){
    const positive=v>=0;const n=positive?v:-1-v;return head(positive?0:1,n);
  }
  if(typeof v==='string')return Buffer.concat([head(3,Buffer.byteLength(v)),Buffer.from(v)]);
  if(Buffer.isBuffer(v))return Buffer.concat([head(2,v.length),v]);
  if(v instanceof Map)return Buffer.concat([head(5,v.size),...Array.from(v.entries()).flatMap(([k,x])=>[encode(k),encode(x)])]);
  throw Error('unsupported_test_cbor');
}
function fixture() {
  const {publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});
  const jwk=publicKey.export({format:'jwk'});
  const cose=new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]);
  const rawId=Buffer.alloc(32,23);
  const counter=Buffer.alloc(4),credentialLength=Buffer.alloc(2);credentialLength.writeUInt16BE(rawId.length);
  const auth=Buffer.concat([sha(host),Buffer.from([0x45]),counter,Buffer.alloc(16),credentialLength,rawId,encode(cose)]);
  const attestation=encode(new Map([['fmt','none'],['attStmt',new Map()],['authData',auth]]));
  const challenge=b64(Buffer.alloc(32,19));
  return {attestationObject:b64(attestation),
    clientDataJSON:b64(JSON.stringify({type:'webauthn.create',challenge,origin,crossOrigin:false})),
    challenge,rpId:host,origin,credentialId:b64(rawId),jwk};
}
test('ES256 device registration binds signed challenge, RP, origin and credential ID',()=>{
  const f=fixture();
  const proof=verifyRegistration(f);
  assert.equal(proof.credentialId,f.credentialId);
  assert.equal(proof.publicJwk.x,f.jwk.x);
  assert.equal(proof.publicJwk.y,f.jwk.y);
  assert.equal(proof.counter,0);
});
test('registration rejects wrong challenge/origin/RP/credential ID',()=>{
  const f=fixture();
  for(const patch of [
    {challenge:b64(Buffer.alloc(32,5))},{origin:'https://wrong.example.org'},
    {rpId:'wrong.example.org'}, {credentialId:b64(Buffer.alloc(32,1))},
  ])assert.throws(()=>verifyRegistration({...f,...patch}));
});
