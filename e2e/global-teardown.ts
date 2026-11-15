import { existsSync, readFileSync } from 'node:fs';

/**
 * Fail the run when a kill recorded in `e2e/verdict-mutations.json` did not
 * actually happen in it.
 *
 * Each ledger entry whose `killedBy.runner` is "playwright" names a test and
 * the marker that test asserts. `markers.ts` writes every (test, marker) pair
 * it really executed to a run-scoped sink. This teardown reads both and fails
 * when a claimed pair is missing.
 *
 * That is the whole reason the ledger can be trusted. A record is a claim
 * about a run; without this, a claim could sit in the file for months after the
 * assertion backing it was renamed, moved or deleted, and nothing would say so.
 * `crypto-lab-hidden-bit` and `crypto-lab-pqxdh-wire` make the same choice for
 * the same reason.
 *
 * It is deliberately scoped to the full-suite run: a single-test run
 * (`-g`) executes one test, so almost every pair would be missing and the
 * teardown would report a fact about the command rather than about the lab.
 * Set `MARKER_AUDIT=off` for such a run, which is what `scripts/mutate.mjs`
 * does NOT do -- it runs the whole claims suite precisely so this check stays
 * live.
 */
export default function globalTeardown(): void {
  if (process.env.MARKER_AUDIT === 'off') return;
  const sink = process.env.MARKER_SINK ?? 'test-results/markers.jsonl';
  // A path relative to the project root: Playwright runs from there, and so
  // does the mutation runner's isolated tree, while `import.meta.url` depends
  // on whether the spec was transpiled to ESM or CJS.
  const ledger = JSON.parse(readFileSync('e2e/verdict-mutations.json', 'utf8')) as {
    mutations: Record<string, { killedBy: { runner: string; test?: string; marker?: string } }>;
  };

  const executed = new Set<string>();
  if (existsSync(sink)) {
    for (const line of readFileSync(sink, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      const { test, marker } = JSON.parse(line) as { test: string; marker: string };
      executed.add(`${test}::${marker}`);
    }
  }

  const missing: string[] = [];
  for (const [id, m] of Object.entries(ledger.mutations)) {
    if (m.killedBy.runner !== 'playwright') continue;
    const key = `${m.killedBy.test}::${m.killedBy.marker}`;
    if (!executed.has(key)) missing.push(`${id}: no test "${m.killedBy.test}" asserted marker "${m.killedBy.marker}"`);
  }

  if (missing.length) {
    throw new Error(
      'verdict-mutations.json records kills that this run did not perform:\n  ' +
        missing.join('\n  ') +
        '\n\nEither the assertion was renamed or removed, or the ledger entry is stale. ' +
        'A recorded kill that nothing executes is a claim with nothing behind it.',
    );
  }
}
