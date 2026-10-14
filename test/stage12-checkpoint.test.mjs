import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {deploymentIdentity} from '../scripts/deployment-identity.mjs';
import {protectedPath} from '../src/stage11-device-proof.mjs';
import {RULE_IDS,decide} from '../src/decider.mjs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
test('stage12 config, signed dashboard route and deployment metadata stay aligned',()=>{
 const c=JSON.parse(read('aleph.config.json'));
 assert.equal(c.step,12);assert(c.allowedRoutes.includes('GET /api/war-room'));
 assert(c.allowedRoutes.includes('POST /api/restore'));assert.equal(c.restoreRoute,'/api/restore');
 const dep=deploymentIdentity({VERCEL_GIT_PROVIDER:'github',
  VERCEL_GIT_REPO_OWNER:'yeaun12',VERCEL_GIT_REPO_SLUG:'choi-bujang-secret-vault',
  VERCEL_GIT_COMMIT_SHA:'a'.repeat(40),
  VERCEL_URL:'choi-bujang-secret-vault-stage12.vercel.app'},c);
 assert.equal(dep.step,12);assert.deepEqual(dep.allowedRoutes,c.allowedRoutes);
 assert.equal(dep.judgeIssuer,c.judgeIssuer);
 assert.equal(protectedPath('GET','/api/war-room'),true);
 assert.equal(protectedPath('POST','/api/war-room'),false);
 assert.equal(protectedPath('GET','/api/war-room?debug=1'),false);
});
test('build and self-check explicitly support 12 and retain recovery checks',()=>{
 assert.match(read('scripts/build-public.mjs'),/\b12\]\.includes\(config\.step\)/);
 assert.match(read('scripts/deployment-identity.mjs'),/\b12\]\.includes\(config\?\.step\)/);
 const c=read('src/attack-check.mjs');
 assert.match(c,/\b12\]\.includes\(config\.step\)/);
 assert.match(c,/anonymous_war_room_read_denied/);
 assert.match(c,/room\.status === 401 && await hasJsonError\(room\)/);
 assert.match(c,/src\/stage10-self-check\.mjs/);
});
test('no invented 41-case results or actual revocation claims',()=>{
 assert.match(read('public/stage12-check-matrix.mjs'),/official41:'unverified'/);
 assert.match(read('public/stage12-check-matrix.mjs'),/result:'not_executed'/);
 const s=read('src/stage12-war-room.mjs');
 assert.match(s,/status: 'not_executed'/);assert.match(s,/completedCount: null/);
 assert.doesNotMatch(s,/select\('title|select\('content/);
});
test('decider returns only registered rule ids for a denied fixture',async()=>{
 assert.deepEqual([...RULE_IDS],['device_registered','step_up_required','resource_scope']);
 const req={requestId:'8daed994-8fe1-4295-a68a-303159882425',
  deviceRegistered:false,method:'GET',path:'/notes'};
 const answer=await decide(req);
 assert.equal(answer.schema,'aleph.decision.v1');
 assert.equal(answer.requestId,req.requestId);
 assert.equal(answer.decision,'deny');
 assert(answer.ruleIds.every(x=>RULE_IDS.includes(x)));
});
