import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {SCENARIOS,blankResults,recordResult,summarizeResults} from '../public/stage12-check-matrix.mjs';
const meta={requestId:'8daed994-8fe1-4295-a68a-303159882425',requestIdSource:'client',
 observedAt:'2026-10-14T03:00:00.000Z'};
test('all stages 1-11 have normal/denied scenarios; none is pre-passed',()=>{
 const rows=blankResults();assert.equal(rows.length,24);
 for(let s=1;s<=11;s++)for(const d of ['normal','denied'])
  assert(rows.some(x=>x.stage===s&&x.direction===d));
 assert(rows.every(x=>x.result==='not_executed'&&x.actual===null&&x.requestId===null));
 assert.equal(summarizeResults(rows).official41,'unverified');
});
test('real HTTP 200 and 403 provide distinct observed allow/deny, not global pass',()=>{
 let rows=blankResults();
 rows=recordResult(rows,{id:'signed_notes',status:200,...meta});
 rows=recordResult(rows,{id:'unsigned_notes',status:403,...meta});
 const s=summarizeResults(rows);
 assert.equal(s.measured,2);assert.equal(s.matched,2);
 assert(s.allowedObserved&&s.deniedObserved);
 assert.equal(rows.find(x=>x.id==='cross_owner').result,'not_executed');
});
test('unexpected response and failed request never produce pass',()=>{
 let rows=blankResults();
 rows=recordResult(rows,{id:'anonymous_notes',status:200,...meta});
 rows=recordResult(rows,{id:'signed_notes',status:null,...meta});
 assert.equal(rows.find(x=>x.id==='anonymous_notes').result,'mismatch');
 assert.equal(rows.find(x=>x.id==='signed_notes').result,'request_error');
 assert.equal(summarizeResults(rows).allowedObserved,false);
});
test('cannot falsely measure manually reserved cases',()=>{
 assert.throws(()=>recordResult(blankResults(),{id:'cross_owner',status:404,...meta}),/manual_check/);
 assert.throws(()=>recordResult(blankResults(),{id:'nonexistent',status:200,...meta}),/unknown_check/);
});
test('browser checks use only GET, keep API bodies and credentials out of evidence',()=>{
 const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
 const start=html.indexOf('async function runVerificationMatrix()');
 const end=html.indexOf('function showAuthError(',start);
 assert(start>0&&end>start);
 const fragment=html.slice(start,end);
 assert.match(fragment,/method:'GET'/);
 assert.match(fragment,/response\.status/);
 assert.match(fragment,/signProtectedRequest\(session,'GET',path,''\)/);
 assert.doesNotMatch(fragment,/localStorage|sessionStorage|indexedDB|\.json\(|\.text\(|method:'POST'/);
});
