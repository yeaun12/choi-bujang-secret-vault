// XDR-06 synthetic replay of destination-deny staging; not an ALEPH judge.
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { respond, isDestinationDenied } from '../xdr/exfiltration/respond.mjs';

export async function replayExfiltration({
  fixturePath = 'xdr/fixtures/exfiltration.json',
  stateDir = 'xdr',
  now,
} = {}) {
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  if (fixture?.moduleKey !== 'exfiltration' || !Array.isArray(fixture.alerts))
    throw new TypeError('invalid_exfiltration_fixture');
  const projected = projectAlerts(fixture);
  if (projected.length !== fixture.alerts.length)
    throw new Error('exfiltration_projection_count_mismatch');
  const options = { stateDir, ...(now === undefined ? {} : { now }) };
  const counts = { block: 0, alert: 0, record: 0 };
  const responseCounts = { block: 0, alert: 0, record: 0 };
  let stagedBlocks = 0;
  let normalBlockedCount = 0;
  for (const alert of fixture.alerts) {
    const judgment = decide(alert);
    if (!Object.hasOwn(counts, judgment?.action))
      throw new TypeError('invalid_exfiltration_decision');
    counts[judgment.action]++;
    const applied = await respond(alert, judgment, options);
    if (!Object.hasOwn(responseCounts, applied.action))
      throw new TypeError('invalid_exfiltration_response');
    responseCounts[applied.action]++;
    if (applied.stagedBlock) stagedBlocks++;
    if (judgment.action === 'record' && await isDestinationDenied({
      sourceIp: alert?.data?.srcip,
      account: alert?.data?.srcuser,
      destinationIp: alert?.data?.dstip,
    }, options)) normalBlockedCount++;
  }
  return {
    moduleKey: 'exfiltration',
    fixtureKind: 'synthetic-training',
    judgeVerified: false,
    total: fixture.alerts.length,
    extractedCount: projected.length,
    counts,
    responseCounts,
    stagedBlocks,
    normalBlockedCount,
    enforcement: 'local-destination-deny-candidates-only; not-attached-to-live-sdp',
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await replayExfiltration(), null, 2));
  } catch (err) {
    console.error('Exfiltration replay failed: ' + (err?.name ?? 'Error'));
    process.exitCode = 1;
  }
}
