import { expect, test } from '@playwright/test';
import { boot, driveAllStates, expectBaselineNotStale, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where
 * exhibit 1 has encrypted its default message and the other five tabpanels are
 * hidden and UNRENDERED; the shared skip link focused; an empty message whose
 * ciphertext is the IV alone; forty more ciphertexts, which make the IV
 * histogram conclusive; a malformed hex key behind an `aria-invalid` boundary;
 * every disclosure and quick check opened through its own summary and answered
 * wrong and then right; the encryptor switch in both positions, with the amber
 * status line it raises; the IV-replacement recovery alarm and its
 * wrong-subversion-key failure; the step-by-step candidate draw, both while
 * candidates are being discarded and once one is kept; 128 biased ciphertexts,
 * which is the negative-claim fixture; the coin-budget table with its scroll
 * region; exhibit 6's four checks; three hover states; and two focus rings.
 * Every one of those states is scanned, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script, why the lab's defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 */

test('no WCAG A/AA violations across every driven state', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await boot(page);
  await driveAllStates(page, 'dark');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});

test('no WCAG A/AA violations across every driven state at 380px', async ({ page }) => {
  test.setTimeout(1_800_000);
  const errors = watchPageErrors(page);
  await page.setViewportSize(NARROW);
  await boot(page);
  await driveAllStates(page, 'dark @380px');
  expect(errors, errors.join('\n')).toEqual([]);
  expectBaselineNotStale();
  reportCollected();
});
