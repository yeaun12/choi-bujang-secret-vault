import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { projectAlerts, readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { decide as decidePrivilege } from '../xdr/privilege/decide.mjs';
import { respond, isRevoked, enforceZtnaDecision } from '../xdr/privilege/respond.mjs';
import { replayPrivilege } from '../scripts/xdr-run-privilege.mjs';
import { decide as decideZtna } from '../src/decider.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const NOW = '2026-10-14T02:00:00.000Z';
async function sandbox(fn) {
  const stateDir = await mkdtemp(join(tmpdir(), 'xdr05-bonus-'));
  try { return await fn({ stateDir, now: NOW }); }
  finally { await rm(stateDir, { recursive: true, force: true }); }
}
const trusted = a => ({ account: a?.data?.srcuser, sourceIp: a?.data?.srcip });

test('26 privilege alerts project to exactly five harmless fields', async () => {
  assert.equal(fixture.moduleKey, 'privilege');
  assert.equal(fixture.alerts.length, 26);
  const rows = projectAlerts(fixture);
  assert.equal(rows.length, 26);
  assert.deepEqual(rows, await readAlerts('xdr/fixtures/privilege.json'));
  assert.deepEqual(Object.keys(rows[0]),
    ['timestamp','sourceAddress','account','ruleLevel','description']);
  assert.equal(rows[0].account, 'user01');
  assert.equal(rows[0].ruleLevel, 12);
  assert.ok(!Object.hasOwn(rows[0], 'group'));
});

test('reader redacts credential-looking descriptions and never projects passwords', () => {
  const rows = projectAlerts([{
    timestamp:'2026-09-27T09:00:00Z',
    rule: { level:12, description: '승격 password=SECRET123 token=HIDDEN456 Bearer ABCDEF' },
    data: { srcip:'192.0.2.9', srcuser:'user01', password:'SENSITIVE_BLOB' },
  }]);
  const encoded=JSON.stringify(rows);
  for (const secret of ['SECRET123','HIDDEN456','ABCDEF','SENSITIVE_BLOB'])
    assert.ok(!encoded.includes(secret));
  assert.equal(projectAlerts([null]).length,1);
  assert.throws(()=>projectAlerts({bad:true}),TypeError);
});

test('five MITRE-backed privilege patterns have one-line rationales and judge constants', async () => {
  const data=JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url),'utf8'));
  const source=await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url),'utf8');
  assert.equal(data.patterns.length,5);
  for(const p of data.patterns){
    assert.ok(p.name&&p.condition&&p.rationale);
    assert.ok(!p.rationale.includes('\n'));
    assert.ok(source.includes(p.name));
  }
  assert.doesNotMatch(source,/(?:^|\n)\s*import\s/m);
  assert.doesNotMatch(source,/\b(?:readFile|writeFile|fetch|require|process\.env)\s*(?:\(|\[)/);
});

test('confirmed escalation stages 15-minute account and IP scoped denial with evidence', async () =>
  sandbox(async o=>{
    const alert=fixture.alerts[0];
    const out=await respond(alert,decidePrivilege(alert),o);
    assert.equal(out.action,'block');
    assert.equal(out.stagedBlock,true);
    assert.equal(out.expiresAt,'2026-10-14T02:15:00.000Z');
    assert.equal(out.evidenceAlertId,'pv-01');
    assert.equal(await isRevoked(trusted(alert),o),true);
    assert.equal(await isRevoked({account:'other-account',sourceIp:alert.data.srcip},o),false);
    assert.equal(await isRevoked({account:'user01',sourceIp:'192.0.2.240'},o),false);
    assert.equal(await isRevoked(trusted(alert),{...o,now:out.expiresAt}),false);
    const rules=JSON.parse(await readFile(join(o.stateDir,'privilege/deny-rules.json'),'utf8'));
    assert.equal(rules.rules.length,1);
    assert.equal(rules.rules[0].ruleId,'xdr-05:pv-01');
    assert.equal(rules.rules[0].sourceAccount,'user01');
    assert.equal(rules.rules[0].evidenceAlertId,'pv-01');
    const log=await readFile(join(o.stateDir,'alerts.log'),'utf8');
    assert.equal(log.trim().split('\n').length,1);
    assert.doesNotMatch(log,/user01|192\.0\.2\.|203\.0\.113\.|password|token/i);
  }));

test('uncertain event only alerts; routine event cannot be revoked by forged block', async () =>
  sandbox(async o=>{
    const suspicious=fixture.alerts[9];
    const normal=fixture.alerts[17];
    assert.equal((await respond(suspicious,decidePrivilege(suspicious),o)).action,'alert');
    assert.equal((await respond(normal,{action:'block',confidence:1,reason:'fake'},o)).action,'record');
    assert.equal(await isRevoked(trusted(suspicious),o),false);
    assert.equal(await isRevoked(trusted(normal),o),false);
    await assert.rejects(readFile(join(o.stateDir,'privilege/deny-rules.json'),'utf8'),
      error=>error?.code==='ENOENT');
    const log=await readFile(join(o.stateDir,'alerts.log'),'utf8');
    assert.equal(log.trim().split('\n').length,1);
  }));

test('a confirmed event missing IP, account or evidence ID cannot create a denial', async () =>
  sandbox(async o=>{
    const a=fixture.alerts[0];
    const noIp=structuredClone(a);delete noIp.data.srcip;
    const noAccount=structuredClone(a);delete noAccount.data.srcuser;
    for(const alert of [noIp,noAccount,{...a,id:null}]){
      const out=await respond(alert,{action:'block',confidence:0.98,reason:'test'},o);
      assert.equal(out.stagedBlock,false);
    }
    assert.equal(await isRevoked(trusted(a),o),false);
    assert.equal(await isRevoked({},o),false);
  }));

test('replaying the same evidence does not accumulate duplicate rules', async () =>
  sandbox(async o=>{
    const a=fixture.alerts[0];
    await respond(a,decidePrivilege(a),o);
    await respond(a,decidePrivilege(a),o);
    const rules=JSON.parse(await readFile(join(o.stateDir,'privilege/deny-rules.json'),'utf8'));
    assert.equal(rules.rules.length,1);
  }));

test('real ZTNA five-field shape is preserved; only mapped account and source are denied', async () =>
  sandbox(async o=>{
    const base=await decideZtna({
      schema:'aleph.decision.v1',requestId:'fixture-05',
      classId:'class_fixture',projectId:'project_fixture',
      subjectId:'learner_fixture',deviceId:'a'.repeat(16),
      service:'notes',method:'GET',path:'/notes/demo',route:'GET /notes/:id',
      queryLength:0,querySha256:'',deviceRegistered:true,
      stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],
      signals:{source:'none',region:'unknown',network:'unknown',hour:9},
    });
    assert.equal(base.decision,'allow');
    const a=fixture.alerts[0];await respond(a,decidePrivilege(a),o);
    const changed=await enforceZtnaDecision(base,trusted(a),o);
    assert.deepEqual(Object.keys(changed),['schema','requestId','decision','reasonCode','ruleIds']);
    assert.equal(changed.decision,'deny');
    assert.equal(changed.reasonCode,'resource_access_denied');
    assert.deepEqual(changed.ruleIds,['resource_scope']);
    assert.equal((await enforceZtnaDecision(base,{account:'user01',sourceIp:'192.0.2.200'},o)).decision,'allow');
    assert.equal((await enforceZtnaDecision(base,{account:'other-user',sourceIp:a.data.srcip},o)).decision,'allow');
    const alreadyDenied={...base,decision:'deny',reasonCode:'device_not_registered'};
    assert.deepEqual(await enforceZtnaDecision(alreadyDenied,trusted(a),o),alreadyDenied);
    assert.equal(base.decision,'allow');
  }));

test('offline replay produces 9 block, 8 alert, 9 record, no normal account revocations', async () =>
  sandbox(async o=>{
    const output=await replayPrivilege({fixturePath:'xdr/fixtures/privilege.json',...o});
    assert.equal(output.total,26);
    assert.equal(output.extractedCount,26);
    assert.deepEqual(output.counts,{block:9,alert:8,record:9});
    assert.deepEqual(output.responseCounts,output.counts);
    assert.equal(output.stagedBlocks,9);
    assert.equal(output.normalBlockedCount,0);
    assert.equal(output.judgeVerified,false);
    const rules=JSON.parse(await readFile(join(o.stateDir,'privilege/deny-rules.json'),'utf8'));
    assert.equal(rules.rules.length,9);
    for(const alert of fixture.alerts.slice(17))
      assert.equal(await isRevoked(trusted(alert),o),false,alert.id);
    const log=await readFile(join(o.stateDir,'alerts.log'),'utf8');
    assert.equal(log.trim().split('\n').length,17);
    assert.doesNotMatch(log,/password=|token=|user01|user02|203\.0\.113\./i);
  }));
