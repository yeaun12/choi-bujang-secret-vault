// XDR-04 local replay with staged ZTNA decision checks. Not an ALEPH judge.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectAlerts } from '../xdr/persistence/read-alerts.mjs';
import { decide } from '../xdr/persistence/decide.mjs';
import { respond, isDenied } from '../xdr/persistence/respond.mjs';

export async function replayPersistence({
  fixturePath = 'xdr/fixtures/persistence.json',
  stateDir = 'xdr',
  now,
} = {}) {
  const doc = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (doc?.moduleKey !== 'persistence' || !Array.isArray(doc.alerts))
    throw new TypeError('invalid_persistence_fixture');
  const projected = projectAlerts(doc);
  if (projected.length !== doc.alerts.length)
    throw new Error('persistence_projection_count_mismatch');
  const counts = { block: 0, alert: 0, record: 0 };
  const responseCounts = { block: 0, alert: 0, record: 0 };
  let normalBlockedCount = 0;
  let stagedBlocks = 0;
  for (const alert of doc.alerts) {
    const decision = decide(alert);
    if (!Object.hasOwn(counts, decision?.action)) throw new TypeError('invalid_persistence_decision');
    counts[decision.action]++;
    const applied = await respond(alert, decision, { stateDir, ...(now === undefined ? {} : { now }) });
    responseCounts[applied.action]++;
    if (applied.stagedBlock) stagedBlocks++;
    const src = alert?.data?.srcip;
    if (decision.action === 'record' && typeof src === 'string' &&
        await isDenied(src, { stateDir, ...(now === undefined ? {} : { now }) })) {
      normalBlockedCount++;
    }
  }
  return {
    moduleKey: 'persistence',
    fixtureKind: 'synthetic-training',
    judgeVerified: false,
    total: doc.alerts.length,
    extractedCount: projected.length,
    counts, responseCounts, stagedBlocks, normalBlockedCount,
    enforcement: 'local-staged-rules; trusted-IP-adapter-not-attached-to-live-ingress',
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await replayPersistence();
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error('Persistence replay failed: ' + (err?.name ?? 'Error'));
    process.exitCode = 1;
  }
}
