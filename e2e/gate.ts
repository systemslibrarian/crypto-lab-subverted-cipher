import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditControlNames, formatControlNameFailures } from './control-names';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this fleet used to ship did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the rendering a reduced-motion reader actually gets was never the one
 *     scanned. This gate sets the preference through `emulateMedia`, asserts
 *     from inside the page that it took effect (`test.use({ reducedMotion })`
 *     is a measured no-op on Playwright 1.6x), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. Stripping `hidden` puts all
 *     six tabpanels on screen AT ONCE -- a rendering no reader can reach --
 *     and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure, waited
 *     a fixed 120ms per tab and scanned ONCE at the end. This drive names every
 *     control it touches, asserts a real completion signal after each, and
 *     scans after every step, at 1280 and at 380.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Every surface carrying
 *     this lab's meaning is a `color-mix()` fill axe files under `incomplete`
 *     rather than judging: the four verdict tones, the subverted-encryptor
 *     status line, the negative-claim box, both pill states, the callouts and
 *     the shared top bar's ink.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE.
 *     `nontext.ts` measures every control at every driven state, and
 *     `expectNoHorizontalOverflow` adds the 1.4.10 check axe has no rule for --
 *     which matters here, where the page paints 112-character hex runs, a
 *     16-column bit grid and a six-column table of counts.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it. Transitions
 * also drain in waves rather than in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves -- hence six consecutive
 * quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish are excluded from the quiescence test rather
 * than waited on, a wall-clock budget inside the page gives up and proceeds,
 * and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels the `.panel` fade and every transition, so `getAnimations()`
 * is normally empty and this returns on the sixth frame. It stays because the
 * shared top bar's `.cl-btn` transitions are declared OUTSIDE the lab's
 * `@media` block -- `* { transition: none !important }` wins today, but that
 * is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' },
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state -- the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has exactly that shape in miniature: `@keyframes fade` starts
 * `from { opacity: 0 }` and every tabpanel rides it. The reduced-motion block
 * cancels it with `animation: none`, which restores the static `opacity: 1`.
 * This assertion is what makes that a measurement rather than a reading.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders on first activation, so a renderer that
 * throws leaves that tabpanel EMPTY -- and an empty region is exactly what a
 * scan reports as perfectly accessible. Attach before `boot`, assert after the
 * drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's hero
 * is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies a
 * second banner today -- but the shared bar's `dedupeBanner()` exists because
 * other labs in this fleet DID ship one, and the hero markup is the part of
 * this page most likely to be re-templated from a lab that uses `<header>`.
 * Asserting the OUTCOME rather than the markup is what catches that edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false;
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * Every list on this page -- the ciphertext log, the candidate list in the
 * step-by-step view, the known-answer rows -- is a `ul.log` or `ul.kat-list`
 * styled `list-style: none`, which is exactly the declaration that makes
 * Safari and VoiceOver DROP the list's implicit role. The panels compensate the
 * documented way: an explicit `role="list"` on the `<ul>` and `role="listitem"`
 * on every child. What is asserted here is the SHAPE of that fix: any explicit
 * role on a `ul`/`ol` must be `list` (any other value orphans every `<li>`
 * under it), and a `role="list"` must never sit on an empty element, because
 * axe applies `aria-required-children` to the explicit role and fails it the
 * day a log renders with no rows.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map((e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`),
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children',
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page -- including the lab's DEFAULTS,
 * which are never assumed.
 *
 * SHARED SETUP ASSERTS STRUCTURE AND NEVER PRODUCT COPY. It runs before EVERY
 * test that imports it, so an assertion here fails all of them at once, under
 * whatever name those tests carry. On 2026-09-26 crypto-lab-mceliece-gate
 * changed one textarea's default string; its gate.ts still asserted the old
 * sentence, boot() threw, every a11y test failed, the deploy was skipped, and
 * the step that went red was called "Accessibility gate" -- a report naming the
 * wrong subject. So: the control exists, the arrival panel is the one that
 * ships, counts, [hidden]/toBeEmpty on lazily-rendered panels, a default
 * matching a SHAPE (/^[0-9a-f]{32}$/). What a string SAYS belongs in
 * claims.spec.ts, where a failure names copy as the subject.
 */
export async function boot(page: Page): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful.
  page.setDefaultTimeout(30_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true);
  // Dark is the only theme, pinned by the head script and by the attribute on
  // <html> itself, so it holds with JS off.
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('.tab-btn')).toHaveCount(6);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]'),
  ).toHaveCount(0);

  // ── The arrival state: exhibit 1 active and ALREADY ENCRYPTED ───────────
  // renderHonestPanel encrypts its default message at mount, so first paint
  // carries a real verdict rather than a placeholder. The other five panels
  // are rendered lazily: hidden AND EMPTY until their tab is first activated --
  // asserted, because "empty" is this lab's tell that a renderer threw.
  await expect(page.locator('#honest-roundtrip .verdict-pass')).toBeVisible();
  await expect(page.locator('#honest-log .log-row')).toHaveCount(1);
  for (const id of ['swap', 'iv', 'bias', 'budget', 'unique']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // ── Every shipped control default ───────────────────────────────────────
  // A SHAPE, not a sentence: a 32-hex key is structural, the message a product
  // string. Asserting the string here would make every a11y test depend on one
  // line of copy.
  await expect(page.locator('#honest-key')).toHaveValue(/^[0-9a-f]{32}$/);
  await expect(page.locator('#honest-key')).toHaveAttribute('aria-invalid', 'false');
  await expect(page.locator('#honest-msg')).not.toHaveValue('');
  // The five known-answer rows are computed on load, not asserted from a file.
  await expect(page.locator('#honest-kats .kat-row')).toHaveCount(5);

  // ── Disclosures ship shut ───────────────────────────────────────────────
  await expect(page.locator('#panel-honest details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, 'first paint');
}

/**
 * Assert that the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are 112-character ciphertext hex runs that rely on
 * `overflow-wrap: anywhere` rather than a scroll region, plus a 16-column bit
 * grid and a two-column `.split` that collapses at 760px -- so the shapes at
 * risk are a new unwrapped `<code>` run and a grid item whose automatic minimum
 * size is the min-content of a long line. At 380px that is precisely what this
 * check exists to catch. Exhibit 5's table is deliberately inside its own
 * `overflow-x: auto` region, which is the one sanctioned exception and is why
 * the clipped-ancestor test below exists.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width -- naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has exactly one scroller -- exhibit 5's `.table-wrap` -- and it
 * ships with `tabindex="0"`, `role="region"` and an `aria-label`. The
 * assertion runs at every state anyway, because the requirement materialises
 * the moment someone reaches for `overflow-x: auto` on another wide value, and
 * a scroller born without a keyboard route is invisible to axe.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      );
  });
  expect(Array.from(new Set(unreachable)), `scrolling regions with no keyboard route in state: ${label}`).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden` DO
 * remove an element from the tab order, so those are skipped rather than
 * flagged. The `hidden` tabpanels here take the `display: none` route, which is
 * why five panels' worth of controls are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with full
 * opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) effective *= parseFloat(getComputedStyle(n).opacity);
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`,
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing, so
 * one run enumerates every defect instead of stopping at the first. It is a
 * debugging aid only: it is never set in CI, and a run with it set fails at the
 * end anyway, so a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * IT IS CALLED FROM `scan()`, deliberately. Fleet-wide this oracle had been
 * called from inside a soft wrapper AFTER its `if (!COLLECTING) return` guard --
 * so in a strict run, which is every run in CI, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves clean
 * on an oracle that had never looked.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive: it has
 * either been fixed -- delete the entry, which is the point -- or the drive
 * stopped reaching the state that shows it, which is a coverage regression.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state -- see `expectNotBlank`.
 *  - `violations` -- the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` -- axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain is `color-contrast`,
 *    and only because the next assertion computes those ratios arithmetically.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish -- including `aria-prohibited-attr`, where an `aria-label` on a
 *    role-less element hides.
 *  - arithmetic contrast -- composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted: SC
 *    1.4.3 is about what a reader SEES, and this page hides verdict glyphs, the
 *    switch knob, the IV histogram and the 128-cell bit grid.
 *  - non-text contrast and generated content -- SC 1.4.11, ratcheted.
 *  - keyboard reachability of scrolling regions -- WCAG 2.1.1.
 *  - no focusable element that paints nothing -- WCAG 2.4.3/2.4.7.
 *  - reflow -- WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // At EVERY state, not only at boot. Every log on this page is rebuilt on
  // every render, and a `role="list"` that renders with no rows is an
  // `aria-required-children` failure that axe files under `incomplete` -- which
  // is exactly the bucket a violations-only gate never reads. Four states
  // reached it before the panels learned to render an empty-state row.
  await assertListSemantics(page);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first.
  // Chained as `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs
  // those FOUR best-practice rules and NOT ONE WCAG RULE, while a green result
  // reads exactly like a full A/AA pass.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them -- and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s,
  // one `<main>`, two `<section class="side">` columns and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({ state: label, id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8) }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // axe's `label` rule accepts a bare `placeholder` as an accessible name, so a
  // deleted label can leave this gate green. See `control-names.ts`.
  const unnamed = formatControlNameFailures(await auditControlNames(page));
  softExpect(unnamed, `form controls named only by placeholder/title in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted -- axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the ONLY
  // thing that ever measures it.
  const hiddenContrast = Array.from(
    new Set(formatContrastFailures(await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true))),
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: exhibit 1
 *    active with one ciphertext already encrypted, five panels hidden and
 *    unrendered, every disclosure shut.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    never in the DOM. Each of the six is activated through its real tab button
 *    and scanned in its own driven states.
 *
 *  - EVERY VERDICT TONE AND EVERY FAILURE STATE. A malformed hex key paints
 *    `aria-invalid` and a failure message; a wrong subversion key turns the
 *    recovery verdict from ALARM to FAIL; the repeated-IV check turns red only
 *    after a reset re-leaks the key. None of these is reachable without doing
 *    something deliberate, and none would otherwise be scanned.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, and `.tab-btn`,
 *    `.btn-ghost` and `.cl-btn` all repaint on hover.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict's text, a row count, `aria-selected`, `aria-checked`.
 */
export async function driveAllStates(page: Page, label: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${label} / ${s}`);

  await scanAt('arrival: exhibit 1 encrypted once, five panels unrendered, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── Exhibit 1: the honest encryptor ─────────────────────────────────────
  await page.locator('#honest-encrypt-empty').click();
  await expect(page.locator('#honest-log .log-msg-empty')).toHaveCount(1);
  await scanAt('exhibit 1: an empty message, whose ciphertext is the IV alone');

  await page.locator('#honest-encrypt-40').click();
  // 42 rows exist; eight are shown. The histogram check is conclusive from 32.
  await expect(page.locator('[data-verdict="honest-iv-histogram"]')).toHaveAttribute('data-state', 'pass');
  await scanAt('exhibit 1: 42 ciphertexts, the IV histogram now conclusive');

  await page.locator('#honest-key').fill('not-a-key');
  await expect(page.locator('#honest-key')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#honest-key-status')).toContainText('hex');
  await scanAt('exhibit 1: a malformed key — aria-invalid boundary and a status message');

  await page.locator('#honest-key').fill('000102030405060708090a0b0c0d0e0f');
  await expect(page.locator('#honest-key')).toHaveAttribute('aria-invalid', 'false');

  await page.locator('#panel-honest details.disclosure > summary').click();
  await expect(page.locator('#panel-honest details.disclosure[open]')).toHaveCount(1);
  await scanAt('exhibit 1: the IV disclosure open');

  await page.locator('#panel-honest details.learner-check > summary').click();
  await page.locator('#panel-honest .check-opt').first().click();
  await expect(page.locator('#panel-honest .pill-bad')).toBeVisible();
  await scanAt('exhibit 1: the quick check answered wrong — the Not quite pill');

  await page.locator('#panel-honest .check-opt').nth(1).click();
  await expect(page.locator('#panel-honest .pill-ok')).toBeVisible();
  await scanAt('exhibit 1: the quick check answered right — the Correct pill');

  // ── Exhibit 2: the switch ───────────────────────────────────────────────
  await openTab(page, /Swap the code/, '#panel-swap');
  await expect(page.locator('#swap-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('[data-verdict="swap-fbits"]')).toBeVisible();
  await scanAt('exhibit 2: the honest encryptor installed, F agreeing by chance');

  await page.locator('#swap-encrypt-8').click();
  await expect(page.locator('#swap-log .log-row')).toHaveCount(8);
  await scanAt('exhibit 2: nine honest ciphertexts, eight shown');

  await page.locator('#swap-switch').click();
  await expect(page.locator('#swap-switch')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('#swap-status')).toHaveClass(/is-subverted/);
  await scanAt('exhibit 2: the subverted encryptor installed — the amber status line');

  await page.locator('#swap-encrypt-8').click();
  await expect(page.locator('[data-verdict="swap-fbits"]')).toHaveAttribute('data-state', 'alarm');
  await scanAt('exhibit 2: eight subverted ciphertexts, F agreeing every time');

  await page.locator('#panel-swap details.learner-check > summary').click();
  await page.locator('#panel-swap .check-opt').first().click();
  await expect(page.locator('#panel-swap .pill-bad')).toBeVisible();
  await scanAt('exhibit 2: its quick check answered wrong');

  await page.locator('#panel-swap details.disclosure > summary').click();
  await expect(page.locator('#panel-swap details.disclosure[open]')).toHaveCount(1);
  await scanAt('exhibit 2: the theorem disclosure open');

  // ── Exhibit 3: IV replacement ───────────────────────────────────────────
  await openTab(page, /IV replacement/, '#panel-iv');
  await expect(page.locator('[data-verdict="iv-recovery"]')).toHaveAttribute('data-state', 'alarm');
  await scanAt('exhibit 3: the key recovered from the first ciphertext — the alarm verdict');

  await page.locator('#iv-holderkey').fill('ffeeddccbbaa99887766554433221100');
  await expect(page.locator('[data-verdict="iv-recovery"]')).toHaveAttribute('data-state', 'fail');
  await scanAt('exhibit 3: the second panel trying the wrong key — KEY NOT RECOVERED');

  await page.locator('#iv-holderkey').fill('2b7e151628aed2a6abf7158809cf4f3c');
  await expect(page.locator('[data-verdict="iv-recovery"]')).toHaveAttribute('data-state', 'alarm');

  await page.locator('#iv-switch').click();
  await expect(page.locator('#iv-switch')).toHaveAttribute('aria-checked', 'false');
  await scanAt('exhibit 3: the honest encryptor, with nothing in the IV to recover');

  // ── Exhibit 4: biased ciphertexts ───────────────────────────────────────
  await openTab(page, /Biased ciphertexts/, '#panel-bias');
  await expect(page.locator('[data-verdict="bias-recovery"]')).toHaveAttribute('data-state', 'neutral');
  await expect(page.locator('[data-verdict="bias-step"]')).toBeVisible();
  await scanAt('exhibit 4: one ciphertext, one bit known, no candidates drawn yet');

  // The step-by-step view: draw until one is kept, so both the discarded and
  // the chosen state are scanned.
  await page.locator('#bias-step-draw').click();
  await expect(page.locator('#bias-stepper .log-row')).toHaveCount(1);
  await scanAt('exhibit 4: one candidate drawn');
  for (let i = 0; i < 12; i++) {
    const state = await page.locator('[data-verdict="bias-step"]').getAttribute('data-state');
    if (state === 'alarm') break;
    await page.locator('#bias-step-draw').click();
  }
  await expect(page.locator('[data-verdict="bias-step"]')).toHaveAttribute('data-state', 'alarm');
  await scanAt('exhibit 4: a candidate kept — the chosen-ciphertext alarm');

  await page.locator('#bias-encrypt-128').click();
  await expect(page.locator('[data-verdict="bias-recovery"]')).toHaveAttribute('data-state', 'alarm');
  await expect(page.locator('[data-verdict="bias-negative-claim"]')).toBeVisible();
  await scanAt('exhibit 4: 128 ciphertexts — every user check green and the key recovered');

  await page.locator('#bias-holderkey').fill('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
  await expect(page.locator('[data-verdict="bias-recovery"]')).toHaveAttribute('data-state', 'fail');
  await scanAt('exhibit 4: the same 128 ciphertexts read with the wrong key — the fail verdict');

  // ── Exhibit 5: the coin budget ──────────────────────────────────────────
  await openTab(page, /How little randomness/, '#panel-budget');
  await expect(page.locator('[data-verdict="budget-rates"]')).toHaveAttribute('data-state', 'neutral');
  await scanAt('exhibit 5: nothing measured yet');

  await page.locator('#budget-trials').fill('100');
  await page.locator('#budget-run').click();
  await expect(page.locator('#budget-table tbody tr')).toHaveCount(8, { timeout: 120_000 });
  await scanAt('exhibit 5: eight budgets measured — the table, its scroll region and the bars');

  await page.locator('#panel-budget details.learner-check > summary').click();
  await page.locator('#panel-budget .check-opt').nth(1).click();
  await expect(page.locator('#panel-budget .pill-ok')).toBeVisible();
  await scanAt('exhibit 5: its quick check answered right');

  // ── Exhibit 6: unique ciphertexts ───────────────────────────────────────
  await openTab(page, /Nothing to choose/, '#panel-unique');
  await expect(page.locator('[data-verdict="unique-tamper"]')).toHaveAttribute('data-state', 'pass', { timeout: 60_000 });
  await expect(page.locator('[data-verdict="unique-nocoins"]')).toHaveAttribute('data-state', 'pass');
  await scanAt('exhibit 6: determinism, tamper rejection, counters and the coinless subverter');

  await page.locator('#unique-advance').click();
  await expect(page.locator('#unique-sigma')).toHaveText('1');
  await scanAt('exhibit 6: the sender advanced to counter 1');

  await page.locator('#panel-unique details.disclosure > summary').click();
  await expect(page.locator('#panel-unique details.disclosure[open]')).toHaveCount(1);
  await scanAt('exhibit 6: the uniqueness-argument disclosure open');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.locator('#unique-run').hover();
  await scanAt('a primary button hovered');

  await page.getByRole('tab', { name: /Honest encryptor/ }).hover();
  await scanAt('an inactive tab hovered — its surface-2 fill repainted');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#unique-msg').focus();
  await expect(page.locator('#unique-msg')).toBeFocused();
  await scanAt('a textarea focused, showing its focus-visible outline');

  await page.getByRole('tab', { name: /Nothing to choose/ }).focus();
  await scanAt('the active tab focused');
}
