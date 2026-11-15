import { expect, type Page, test } from '@playwright/test';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Every verdict this page renders carries `data-verdict="<marker>"` and
 * `data-state`, and every assertion about one goes through `expectVerdict`
 * below. The helper does two things at once:
 *
 *  1. it asserts the verdict's STATE and its TEXT together, so a test cannot
 *     pass on a green tone with the wrong words in it, or on the right words
 *     in the wrong tone;
 *
 *  2. it RECORDS the (test, marker) pair it actually executed, to a run-scoped
 *     sink that `global-teardown.ts` reads.
 *
 * The second half is what makes `verdict-mutations.json` enforceable rather
 * than archival. A ledger entry claims "mutation M3 is killed by this test
 * asserting this marker"; the teardown fails the run when that pair never
 * appeared in the sink. The alternative -- scanning the source for a call --
 * is satisfied by a commented-out one, which has happened elsewhere in this
 * fleet.
 */

const SINK = process.env.MARKER_SINK ?? 'test-results/markers.jsonl';

function recordPair(marker: string): void {
  const title = test.info().title;
  mkdirSync(dirname(SINK), { recursive: true });
  appendFileSync(SINK, `${JSON.stringify({ test: title, marker })}\n`);
}

export type VerdictState = 'pass' | 'fail' | 'alarm' | 'neutral';

/**
 * Assert one rendered verdict, by marker, and record that this test did so.
 * `text` is matched against the verdict's full text content, which includes
 * its heading line and its one-sentence summary.
 */
export async function expectVerdict(
  page: Page,
  marker: string,
  want: { state: VerdictState; text?: RegExp | string },
): Promise<void> {
  const el = page.locator(`[data-verdict="${marker}"]`);
  await expect(el, `verdict "${marker}" must be on screen`).toBeVisible();
  await expect(el, `verdict "${marker}" state`).toHaveAttribute('data-state', want.state);
  if (want.text !== undefined) await expect(el, `verdict "${marker}" text`).toContainText(want.text);
  recordPair(marker);
}

/** The same, for a prose claim carried by `data-claim`. */
export async function expectClaim(page: Page, marker: string, text: RegExp | string): Promise<void> {
  const el = page.locator(`[data-claim="${marker}"]`);
  await expect(el, `claim "${marker}" must be on screen`).toBeVisible();
  await expect(el, `claim "${marker}" text`).toContainText(text);
  recordPair(marker);
}

/** Read a verdict's state without asserting it (for polling a slow panel). */
export async function verdictState(page: Page, marker: string): Promise<string | null> {
  return page.locator(`[data-verdict="${marker}"]`).getAttribute('data-state');
}
