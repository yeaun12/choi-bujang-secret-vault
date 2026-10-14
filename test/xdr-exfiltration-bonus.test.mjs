import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { projectAlerts, readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { decide as decideExfiltration } from '../xdr/exfiltration/decide.mjs';
import { respond, isDestinationDenied, enforceZtnaDecision } from '../xdr/exfiltration/respond.mjs';
import { replayExfiltration } from '../scripts/xdr-run-exfiltration.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
const NOW='2026-10-14T02:00:00.000Z';
const flow=a=>({account:a?.data?.srcuser,sourceIp:a?.data?.srcip,destinationIp:a?.data?.dstip});
async function sandbox(fn){
  const stateDir=await mkdtemp(join(tmpdir(),'xdr06-bonus-'));
  try{return await fn({stateDir,now:NOW});}
  finally{await rm(stateDir,{recursive:true,force:true});}
}

test('30 original exfiltration fixtures each extract exactly five safe fields',async()=>{
  assert.equal(fixture.moduleKey,'exfiltration');
  assert.equal(fixture.alerts.length,30);
  const rows=projectAlerts(fixture);
  assert.equal(rows.length,30);
  assert.deepEqual(rows,await readAlerts('xdr/fixtures/exfiltration.json'));
  assert.deepEqual(Object.keys(rows[0]),['timestamp','sourceAddress','account','ruleLevel','description']);
  assert.equal(rows[0].ruleLevel,12);
  assert.equal(rows[0].account,'user01');
  assert.ok(!Object.hasOwn(rows[0],'bytes'));
  assert.ok(!Object.hasOwn(rows[0],'dstip'));
});

test('projection does not leak passwords, tokens or raw payload fields',()=>{
  const rows=projectAlerts([{
    timestamp:'2026-09-27T09:00:00Z',
    rule:{level:13,description:'Transfer password=SECRET123 token=HIDDEN456 Bearer ABCDEF'},
    data:{srcip:'192.0.2.1',srcuser:'user01',password:'SENSITIVE_BLOB'},
  }]);
  for(const sensitive of ['SECRET123','HIDDEN456','ABCDEF','SENSITIVE_BLOB'])
    assert.ok(!JSON.stringify(rows).includes(sensitive));
  assert.equal(projectAlerts([null]).length,1);
  assert.throws(()=>projectAlerts({invalid:true}),TypeError);
});

test('all T1041/T1048 patterns contain one-line evidence and standalone judge constants',async()=>{
  const data=JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json',import.meta.url),'utf8'));
  const source=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
  assert.equal(data.patterns.length,5);
  for(const p of data.patterns){
    assert.ok(p.name&&p.condition&&p.rationale&&!p.rationale.includes('\n'));
    assert.ok(source.includes(p.name));
    assert.ok(source.includes(p.rationale));
  }
  assert.doesNotMatch(source,/(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source,/\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('one confirmed exfiltration creates destination-specific 15-minute rule',async()=>sandbox(async opts=>{
  const alert=fixture.alerts[0];
  const out=await respond(alert,decideExfiltration(alert),opts);
  assert.equal(out.action,'block');
  assert.equal(out.stagedBlock,true);
  assert.equal(out.evidenceAlertId,'ex-01');
  assert.equal(out.expiresAt,'2026-10-14T02:15:00.000Z');
  assert.equal(await isDestinationDenied(flow(alert),opts),true);
  assert.equal(await isDestinationDenied({...flow(alert),destinationIp:'192.0.2.42'},opts),false);
  assert.equal(await isDestinationDenied({...flow(alert),account:'unrelated'},opts),false);
  assert.equal(await isDestinationDenied({...flow(alert),sourceIp:'192.0.2.89'},opts),false);
  assert.equal(await isDestinationDenied(flow(alert),{...opts,now:out.expiresAt}),false);
  const rules=JSON.parse(await readFile(join(opts.stateDir,'exfiltration/deny-rules.json'),'utf8'));
  assert.equal(rules.rules.length,1);
  assert.equal(rules.rules[0].ruleId,'xdr-06:ex-01');
  assert.equal(rules.rules[0].destinationIp,alert.data.dstip);
  assert.equal(rules.rules[0].evidenceAlertId,'ex-01');
  const log=await readFile(join(opts.stateDir,'alerts.log'),'utf8');
  assert.equal(log.trim().split('\n').length,1);
  assert.doesNotMatch(log,/user01|203\.0\.113\.|192\.0\.2\.|password|token/i);
}));

test('uncertain event is alert-only and forged block never stages a normal transfer',async()=>sandbox(async opts=>{
  const suspicious=fixture.alerts[10];
  const normal=fixture.alerts[20];
  assert.equal((await respond(suspicious,decideExfiltration(suspicious),opts)).action,'alert');
  assert.equal((await respond(normal,{action:'block',confidence:0.99,reason:'forged'},opts)).action,'record');
  assert.equal(await isDestinationDenied(flow(suspicious),opts),false);
  assert.equal(await isDestinationDenied(flow(normal),opts),false);
  await assert.rejects(readFile(join(opts.stateDir,'exfiltration/deny-rules.json'),'utf8'),
    error=>error?.code==='ENOENT');
  assert.equal((await readFile(join(opts.stateDir,'alerts.log'),'utf8')).trim().split('\n').length,1);
}));

test('missing source, destination, account or alert number prevents blocking',async()=>sandbox(async opts=>{
  const alert=fixture.alerts[0];
  for(const key of ['srcip','dstip','srcuser']){
    const bad=structuredClone(alert);
    delete bad.data[key];
    const out=await respond(bad,{action:'block',confidence:0.99},opts);
    assert.equal(out.stagedBlock,false,key);
  }
  assert.equal((await respond({...alert,id:null},decideExfiltration(alert),opts)).stagedBlock,false);
  assert.equal(await isDestinationDenied(flow(alert),opts),false);
  assert.equal(await isDestinationDenied({destinationIp:alert.data.dstip},opts),false);
}));

test('same evidence ID is upserted without duplicate deny entries',async()=>sandbox(async opts=>{
  const alert=fixture.alerts[0];
  await respond(alert,decideExfiltration(alert),opts);
  await respond(alert,decideExfiltration(alert),opts);
  const rules=JSON.parse(await readFile(join(opts.stateDir,'exfiltration/deny-rules.json'),'utf8'));
  assert.equal(rules.rules.length,1);
  assert.equal(rules.rules[0].ruleId,'xdr-06:ex-01');
}));

test('existing ZTNA decision and five-field contract remain intact',async()=>sandbox(async opts=>{
  const base=await decideZtna({
    schema:'aleph.decision.v1',requestId:'local-06',
    classId:'class_fixture',projectId:'project_fixture',
    subjectId:'learner_fixture',deviceId:'a'.repeat(16),
    service:'notes',method:'GET',path:'/notes/demo',route:'GET /notes/:id',
    queryLength:0,querySha256:'',deviceRegistered:true,
    stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],
    signals:{source:'none',region:'unknown',network:'unknown',hour:9},
  });
  assert.equal(base.decision,'allow');
  const attack=fixture.alerts[0];
  await respond(attack,decideExfiltration(attack),opts);
  const denied=await enforceZtnaDecision(base,flow(attack),opts);
  assert.deepEqual(Object.keys(denied),['schema','requestId','decision','reasonCode','ruleIds']);
  assert.equal(denied.decision,'deny');
  assert.equal(denied.reasonCode,'resource_access_denied');
  assert.deepEqual(denied.ruleIds,['resource_scope']);
  assert.equal((await enforceZtnaDecision(base,{...flow(attack),account:'other'},opts)).decision,'allow');
  assert.equal((await enforceZtnaDecision(base,{...flow(attack),destinationIp:'192.0.2.10'},opts)).decision,'allow');
  const preexistingDeny={...base,decision:'deny',reasonCode:'device_not_registered'};
  assert.deepEqual(await enforceZtnaDecision(preexistingDeny,flow(attack),opts),preexistingDeny);
  assert.equal(base.decision,'allow');
}));

test('local 30-event replay yields 10/10/10 and no normal destination blocks',async()=>sandbox(async opts=>{
  const result=await replayExfiltration({fixturePath:'xdr/fixtures/exfiltration.json',...opts});
  assert.equal(result.total,30);
  assert.equal(result.extractedCount,30);
  assert.deepEqual(result.counts,{block:10,alert:10,record:10});
  assert.deepEqual(result.responseCounts,result.counts);
  assert.equal(result.stagedBlocks,10);
  assert.equal(result.normalBlockedCount,0);
  assert.equal(result.judgeVerified,false);
  const rules=JSON.parse(await readFile(join(opts.stateDir,'exfiltration/deny-rules.json'),'utf8'));
  assert.equal(rules.rules.length,10);
  for(const normal of fixture.alerts.slice(20))
    assert.equal(await isDestinationDenied(flow(normal),opts),false,normal.id);
  const log=await readFile(join(opts.stateDir,'alerts.log'),'utf8');
  assert.equal(log.trim().split('\n').length,20);
  assert.doesNotMatch(log,/password=|token=|user01|203\.0\.113\./i);
}));
