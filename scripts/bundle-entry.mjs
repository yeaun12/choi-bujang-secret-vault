// Stage 12 judge checkouts do not include the gitignored personal notes file.
// Create a truthful, non-secret default only when it is absent, and then run
// the unchanged bundle generator in the same Node process.
import { readFileSync, writeFileSync } from 'node:fs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const notesPath = new URL('../bundle-notes.json', import.meta.url);
try {
  readFileSync(notesPath, 'utf8');
} catch (error) {
  if (config.step !== 12 || error?.code !== 'ENOENT') throw error;
  const notes = {
    explanation: 'Stage 12 implements a read-only war-room summary and a verification matrix. Submission checks use five public HTTPS GETs; three write probes and five local recovery tests are recorded as not_run. The official 41-case assault has not been independently verified.',
    blockedAt: null,
  };
  writeFileSync(notesPath, JSON.stringify(notes, null, 2) + '\n', {
    encoding: 'utf8', flag: 'wx',
  });
}
await import('./bundle.mjs');
