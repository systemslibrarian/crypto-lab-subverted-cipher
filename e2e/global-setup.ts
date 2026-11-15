import { mkdirSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Truncate the verdict-marker sink before the run. Without this, a pair
 * recorded by YESTERDAY's run would satisfy today's teardown, and an
 * unperformed kill would read as performed -- which is the exact confusion the
 * sink exists to remove.
 */
export default function globalSetup(): void {
  const sink = process.env.MARKER_SINK ?? 'test-results/markers.jsonl';
  mkdirSync(dirname(sink), { recursive: true });
  rmSync(sink, { force: true });
}
