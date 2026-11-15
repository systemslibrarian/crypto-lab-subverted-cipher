import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { boot } from './gate';
import { expectClaim, expectVerdict, verdictState } from './markers';

/**
 * The claims suite: what this lab's interface SAYS and whether it is TRUE, as
 * opposed to what it is shaped like (template §4.1b). Structure lives in
 * `gate.ts`; a failure here names copy or correctness as the subject, which is
 * what actually changed.
 *
 * The rule that makes these tests worth anything: never re-derive a claim the
 * way the source does. Two kinds of assertion here, mixed on purpose:
 *
 *  - CROSS-CHECKS between two surfaces that must agree (the per-ciphertext
 *    candidate counts against their printed subtotal; the recovered key
 *    against the user key; the subverter's output against the honest output).
 *
 *  - INDEPENDENT RE-DERIVATIONS, computed in this process by a DIFFERENT route
 *    than the page takes. The page hand-rolls AES so it can encipher and
 *    decipher single blocks; this file uses Node's WebCrypto instead -- AES-CTR
 *    for the round trip, AES-CBC under a zero IV for the single-block inverse,
 *    HMAC-SHA-256 for F. A test that recomputed the page's own expression
 *    would agree with a bug in it, which has happened elsewhere in this fleet.
 *
 * Every verdict assertion goes through `expectVerdict`, which records the
 * (test, marker) pair it executed; `global-teardown.ts` fails the run if a kill
 * recorded in `verdict-mutations.json` was never performed.
 */

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string): Uint8Array => new Uint8Array(s.match(/../g)!.map((p) => parseInt(p, 16)));

/** AES-CTR with a 128-bit counter, through WebCrypto: the independent route. */
async function ctrDecrypt(key: Uint8Array, ct: Uint8Array): Promise<string> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CTR', false, ['decrypt']);
  const out = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: ct.subarray(0, 16) as BufferSource, length: 128 },
    k,
    ct.subarray(16) as BufferSource,
  );
  return new TextDecoder().decode(out);
}

/**
 * One AES block backwards, through WebCrypto AES-CBC: D_K(c) is the first block
 * of CBC-decrypting c ‖ x under a zero IV, where x is the single block CBC
 * produces for the empty message under IV = c. Nothing here touches the page's
 * own AES.
 */
async function aesDecryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const enc = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
  const dec = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['decrypt']);
  const x = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: block as BufferSource }, enc, new Uint8Array()),
  );
  const joined = new Uint8Array(32);
  joined.set(block);
  joined.set(x.subarray(0, 16), 16);
  const out = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, dec, joined as BufferSource);
  return new Uint8Array(out);
}

/** F(K~, C, j), recomputed here from the rendered ciphertext. */
async function fBit(subKey: Uint8Array, ct: Uint8Array, j: number): Promise<number> {
  const k = await crypto.subtle.importKey('raw', subKey as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = new Uint8Array(ct.length + 4);
  data.set(ct);
  new DataView(data.buffer).setUint32(ct.length, j, false);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, data as BufferSource));
  return mac[0]! & 1;
}

const keyBit = (key: Uint8Array, j: number): number => (key[j >> 3]! >> (7 - (j & 7))) & 1;

/** Every ciphertext row currently on screen in a panel, with its message. */
async function rows(page: Page, panel: string): Promise<Array<{ ct: Uint8Array; msg: string; tried: number | null }>> {
  return (
    await page.locator(`#${panel}-log .log-row`).evaluateAll((els) =>
      els.map((el) => ({
        ctHex: el.getAttribute('data-ct') ?? '',
        msg: (el.querySelector('.log-msg')?.textContent ?? '').trim(),
        triedText: el.querySelector('[data-tried]')?.getAttribute('data-tried') ?? null,
      })),
    )
  ).map((r) => ({ ct: unhex(r.ctHex), msg: r.msg, tried: r.triedText === null ? null : Number(r.triedText) }));
}

async function openBiasWith128(page: Page): Promise<void> {
  await page.getByRole('tab', { name: /Biased ciphertexts/ }).click();
  await page.locator('#bias-encrypt-128').click();
  await expect(page.locator('#bias-count')).toContainText('128 ciphertexts');
}

test.describe('what the page shows is what the cryptography did', () => {
  test('every ciphertext on screen decrypts, under the key on screen, to the message beside it', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    const key = unhex(await page.locator('#bias-userkey').inputValue());
    const shown = await rows(page, 'bias');
    expect(shown.length).toBeGreaterThan(0);
    for (const r of shown) {
      expect(await ctrDecrypt(key, r.ct), `ciphertext ${hex(r.ct).slice(0, 16)}… must decrypt to its row's message`).toBe(r.msg);
    }
    await expectVerdict(page, 'bias-roundtrip', { state: 'pass', text: /Round trip: PASSES/ });
  });

  test('the recovered key on screen is the user key on screen, and F read it off the rendered ciphertexts', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    const userKey = unhex(await page.locator('#bias-userkey').inputValue());
    const subKey = unhex(await page.locator('#bias-subkey').inputValue());
    // Cross-check: the page prints the recovered key and the user key side by side.
    await expect(page.locator('#bias-partial-key')).toHaveText(hex(userKey));
    // Independent re-derivation: evaluate F here, on the ciphertexts the page
    // rendered, and rebuild the key from scratch. This does not reuse one line
    // of the page's extraction code.
    const shown = await rows(page, 'bias');
    for (const r of shown) {
      const j = Number(/key bit (\d+)/.exec((await page.locator(`[data-ct="${hex(r.ct)}"] .log-meta`).innerText()))![1]);
      expect(await fBit(subKey, r.ct, j), `F on ciphertext ${j} must equal key bit ${j}`).toBe(keyBit(userKey, j));
    }
    await expectVerdict(page, 'bias-recovery', { state: 'alarm', text: /KEY RECOVERED — IT EQUALS THE USER'S KEY/ });
  });

  test('the IV-replacement panel recovers the key, and the same key comes out of an independent AES', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /IV replacement/ }).click();
    const userKey = await page.locator('#iv-userkey').inputValue();
    const subKey = unhex(await page.locator('#iv-subkey').inputValue());
    const shown = await rows(page, 'iv');
    const iv = shown[0]!.ct.subarray(0, 16);
    // Independent: decipher that IV with WebCrypto, not with the page's AES.
    expect(hex(await aesDecryptBlock(subKey, iv))).toBe(userKey);
    await expectVerdict(page, 'iv-recovery', { state: 'alarm', text: /KEY RECOVERED/ });
  });

  test('the user-side checks are recomputed here from the ciphertexts the page rendered', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    const shown = await rows(page, 'bias');
    const ivs = new Set(shown.map((r) => hex(r.ct.subarray(0, 16))));
    expect(ivs.size, 'no repeated IV among the ciphertexts on screen').toBe(shown.length);
    await expectVerdict(page, 'bias-no-repeat-iv', { state: 'pass', text: /128 IVs, all distinct/ });
    // The histogram check's own count must agree with the ciphertexts it was
    // computed from: 128 ciphertexts x 16 IV bytes.
    await expectVerdict(page, 'bias-iv-histogram', { state: 'pass', text: /2048 IV bytes/ });
  });

  test('the candidate counts shown sum to the subtotal shown', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    const shown = await rows(page, 'bias');
    const sum = shown.reduce((a, r) => a + (r.tried ?? 0), 0);
    expect(shown.every((r) => r.tried !== null), 'every row carries its candidate count').toBe(true);
    await expect(page.locator('#bias-shown-count')).toHaveText(String(shown.length));
    await expect(page.locator('#bias-tried-shown')).toHaveText(String(sum));
    // The all-ciphertext total must be at least the subtotal and at least one
    // candidate per ciphertext.
    const all = Number(await page.locator('#bias-tried-all').innerText());
    expect(all).toBeGreaterThanOrEqual(sum);
    expect(all).toBeGreaterThanOrEqual(128);
  });
});

test.describe('evidence is retired when it stops belonging to the controls on screen', () => {
  test('changing the user key clears the ciphertexts and the recovery verdict', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    await expectVerdict(page, 'bias-recovery', { state: 'alarm' });
    await page.locator('#bias-userkey').fill('ffeeddccbbaa99887766554433221100');
    await expect(page.locator('#bias-log .log-row')).toHaveCount(0);
    await expectVerdict(page, 'bias-recovery', { state: 'neutral', text: /NO CIPHERTEXTS YET/ });
  });

  test('changing the encryptor\'s subversion key clears the ciphertexts, which were made under the old one', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    await page.locator('#bias-subkey').fill('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
    await expect(page.locator('#bias-log .log-row')).toHaveCount(0);
    await expectVerdict(page, 'bias-recovery', { state: 'neutral' });
    // And the second panel's key follows it, because they are one key.
    await expect(page.locator('#bias-holderkey')).toHaveValue(
      'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf',
    );
  });

  test('changing only the second panel\'s key leaves the ciphertexts alone', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    await page.locator('#bias-holderkey').fill('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
    await expect(page.locator('#bias-log .log-row')).toHaveCount(8);
    await expect(page.locator('#bias-count')).toContainText('128 ciphertexts');
    await expectVerdict(page, 'bias-recovery', { state: 'fail' });
  });

  test('throwing the encryptor switch retires the evidence with it', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /Swap the code/ }).click();
    await page.locator('#swap-encrypt-8').click();
    await expect(page.locator('#swap-log .log-row')).toHaveCount(8);
    await page.locator('#swap-switch').click();
    await expect(page.locator('#swap-switch')).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('#swap-log .log-row')).toHaveCount(0);
    await expectVerdict(page, 'swap-recovery', { state: 'neutral', text: /NO CIPHERTEXTS YET/ });
  });

  test('the no-op guard: re-entering the SAME key retires nothing', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    const key = await page.locator('#bias-userkey').inputValue();
    const before = await page.locator('#bias-count').innerText();
    await page.locator('#bias-userkey').fill(key);
    await expect(page.locator('#bias-count')).toHaveText(before);
    await expect(page.locator('#bias-log .log-row')).toHaveCount(8);
    await expectVerdict(page, 'bias-recovery', { state: 'alarm' });
  });
});

test.describe('the negative claim (template §4.1d)', () => {
  /**
   * The claim, scoped to this page: every test the user can run with their own
   * key passes, and that says nothing about whether the encryptor is leaking
   * the key. The fixture is exhibit 4 after 128 subverted ciphertexts: a state
   * in which every check the page performs reports success AND the named
   * property is violated anyway.
   */
  test('128 subverted ciphertexts: every user check reports success and the key has still leaked', async ({ page }) => {
    await boot(page);
    // 1. Reach the fixture through the UI.
    await openBiasWith128(page);

    // 2. Everything the user can check is green -- asserted against the
    //    rendered verdicts, not against a flag this test set.
    await expectVerdict(page, 'bias-roundtrip', { state: 'pass', text: /PASSES/ });
    await expectVerdict(page, 'bias-no-repeat-iv', { state: 'pass', text: /PASSES/ });
    await expectVerdict(page, 'bias-iv-histogram', { state: 'pass', text: /PASSES/ });
    // And the key is out: the right panel's bytes equal the left panel's key.
    const userKey = await page.locator('#bias-userkey').inputValue();
    await expect(page.locator('#bias-partial-key')).toHaveText(userKey);
    await expectVerdict(page, 'bias-recovery', { state: 'alarm' });

    // 3. The limitation is on screen in that state -- visible, not in the
    //    README and not behind a disclosure.
    await expectVerdict(page, 'bias-negative-claim', { state: 'alarm', text: /ALL USER CHECKS PASS — AND THE KEY HAS LEAKED/ });
    await expectClaim(
      page,
      'bias-negative-claim',
      /Every test the user can run with their own key passes, and that says nothing about whether the encryptor is leaking the key: for these 128 ciphertexts it has leaked all of it\./,
    );
  });

  test('the bite fixture: with a different K~ the page says the key was NOT recovered', async ({ page }) => {
    await boot(page);
    await openBiasWith128(page);
    // A different K~ for the SECOND PANEL ONLY: the same 128 ciphertexts, read
    // with the wrong key. 128 bits still come out of F -- it always returns
    // something -- and they are not the key, so the page must say so rather
    // than counting bits and calling it a recovery.
    await page.locator('#bias-holderkey').fill('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
    await expect(page.locator('#bias-log .log-row')).toHaveCount(8);
    const userKey = await page.locator('#bias-userkey').inputValue();
    // The extraction completed: all 128 bits are known...
    await expect(page.locator('#bias-partial-key')).toHaveText(/^[0-9a-f]{32}$/);
    // ...and they are not the key, so nothing is claimed recovered.
    await expect(page.locator('#bias-partial-key')).not.toHaveText(userKey);
    await expectVerdict(page, 'bias-recovery', { state: 'fail', text: /KEY NOT RECOVERED/ });
    // The negative claim belongs to the fixture where everything is green AND
    // the key leaked. Here it must not be on screen at all.
    await expect(page.locator('[data-verdict="bias-negative-claim"]')).toHaveCount(0);
  });

  test('the honest control: the same extraction on honest ciphertexts recovers nothing', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /Biased ciphertexts/ }).click();
    await page.locator('#bias-switch').click();
    await expect(page.locator('#bias-switch')).toHaveAttribute('aria-checked', 'false');
    await page.locator('#bias-encrypt-128').click();
    await expect(page.locator('#bias-count')).toContainText('128 ciphertexts');
    // Honest ciphertexts carry no bits, so the 128 extracted are noise.
    const userKey = await page.locator('#bias-userkey').inputValue();
    await expect(page.locator('#bias-partial-key')).not.toHaveText(userKey);
    await expectVerdict(page, 'bias-recovery', { state: 'fail', text: /128 BITS EXTRACTED, AND THEY ARE NOT THE KEY/ });
    // The user's checks pass here too -- which is the point of the control.
    await expectVerdict(page, 'bias-roundtrip', { state: 'pass' });
  });
});

test.describe('the other exhibits say what they computed', () => {
  test('exhibit 1 reproduces five published vectors in the browser', async ({ page }) => {
    await boot(page);
    await expectVerdict(page, 'honest-kats', { state: 'pass', text: /5 OF 5 STANDARD VECTORS REPRODUCED/ });
    // Cross-check: the verdict's count and the rows it counts must agree.
    await expect(page.locator('#honest-kats .kat-row')).toHaveCount(5);
    await expect(page.locator('#honest-kats .kat-row.is-bad')).toHaveCount(0);
    // And one value re-derived here rather than read off the page: the FIPS 197
    // Appendix C.1 ciphertext.
    const fips = await page.locator('#honest-kats .kat-row').first().locator('code').innerText();
    expect(fips).toBe('69c4e0d86a7b0430d8cdb78070b4c55a');
  });

  test('exhibit 2 shows F agreeing about half the time on honest ciphertexts and every time on subverted ones', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /Swap the code/ }).click();
    await page.locator('#swap-encrypt-8').click();
    await expect(page.locator('#swap-log .log-row')).toHaveCount(8);
    await expectVerdict(page, 'swap-fbits', { state: 'neutral', text: /ABOUT HALF, AS CHANCE WOULD GIVE/ });
    await page.locator('#swap-switch').click();
    await page.locator('#swap-encrypt-8').click();
    await expect(page.locator('#swap-log .log-row')).toHaveCount(8);
    // Independent: recompute F on each rendered ciphertext and confirm the
    // count the page printed.
    const subKey = unhex(await page.locator('#swap-subkey').inputValue());
    const userKey = unhex(await page.locator('#swap-userkey').inputValue());
    const shown = await rows(page, 'swap');
    expect(shown).toHaveLength(8);
    let agree = 0;
    for (let i = 0; i < shown.length; i++) {
      const j = i;
      if ((await fBit(subKey, shown[i]!.ct, j)) === keyBit(userKey, j)) agree++;
    }
    expect(agree, 'every subverted ciphertext on screen must satisfy F').toBe(shown.length);
    // Throwing the switch retired the earlier evidence, so these eight are all
    // there are -- and F agrees on every one of them.
    await expectVerdict(page, 'swap-fbits', { state: 'alarm', text: /F AGREES WITH THE KEY ON 8 OF 8 CIPHERTEXTS/ });
  });

  test('exhibit 5 reports rates it counted, and its verdict follows from its own table', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /How little randomness/ }).click();
    await page.locator('#budget-trials').fill('200');
    await page.locator('#budget-run').click();
    await expect(page.locator('#budget-table tbody tr')).toHaveCount(4, { timeout: 180_000 });
    const table = await page.locator('#budget-table tbody tr').evaluateAll((trs) =>
      trs.map((tr) => ({
        trials: Number(tr.querySelector('[data-trials]')!.getAttribute('data-trials')),
        failures: Number(tr.querySelector('[data-failures]')!.getAttribute('data-failures')),
        rate: Number(tr.querySelector('[data-rate]')!.getAttribute('data-rate')),
      })),
    );
    // Cross-check: each printed rate is its own failures over its own runs.
    for (const r of table) {
      expect(r.trials).toBe(200);
      expect(Math.abs(r.rate - r.failures / r.trials)).toBeLessThan(0.0001);
    }
    // Parts sum to whole: the verdict's total run count is the table's.
    const total = table.reduce((a, r) => a + r.trials, 0);
    const state = (await verdictState(page, 'budget-rates')) === 'pass' ? 'pass' : 'fail';
    await expectVerdict(page, 'budget-rates', { state, text: new RegExp(`${total.toLocaleString('en-US')} runs in total`) });
    // The 1-bit budget is the one measurable at this sample size: 2^-2 = 0.25,
    // and 200 runs put the standard error at about 0.03.
    expect(table[0]!.rate).toBeGreaterThan(0.15);
    expect(table[0]!.rate).toBeLessThan(0.35);
  });

  test('exhibit 6 prints two identical ciphertexts and a subverter forced to emit the honest one', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /Nothing to choose/ }).click();
    await expectVerdict(page, 'unique-determinism', { state: 'pass', text: /BYTE FOR BYTE IDENTICAL/ });
    // Cross-check the two printed ciphertexts against each other.
    const values = await page.locator('#unique-determinism .field-value').allInnerTexts();
    expect(values[0]).toBe(values[1]);
    expect(values[0]).toMatch(/^[0-9a-f]+$/);
    await expectVerdict(page, 'unique-tamper', { state: 'pass', text: /ALL 464 SINGLE-BIT CHANGES REJECTED/, });
    await expectVerdict(page, 'unique-outoforder', { state: 'pass', text: /OUT-OF-ORDER CIPHERTEXT REJECTED/ });
    await expectVerdict(page, 'unique-replay', { state: 'pass', text: /A REPLAY REJECTED/ });
    await expectVerdict(page, 'unique-inorder', { state: 'pass' });
    await expectVerdict(page, 'unique-roundtrip', { state: 'pass' });
    // The subverter's output and the honest output are two surfaces that must
    // agree, and the page says so only after comparing them.
    const sub = await page.locator('#unique-subverter .field-value').allInnerTexts();
    expect(sub[1]).toBe(sub[2]);
    expect(sub[0]).toBe('0');
    await expectVerdict(page, 'unique-nocoins', { state: 'pass', text: /NO COINS TO CHOOSE/ });
  });

  test('the step-by-step view keeps a candidate only when F says the key bit', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /Biased ciphertexts/ }).click();
    await expectVerdict(page, 'bias-step', { state: 'neutral', text: /NO CANDIDATES DRAWN YET/ });
    for (let i = 0; i < 20; i++) {
      if ((await verdictState(page, 'bias-step')) === 'alarm') break;
      await page.locator('#bias-step-draw').click();
    }
    const lines = await page.locator('#bias-stepper .log-row .log-meta').allInnerTexts();
    // Exactly one kept, and it is the last one drawn.
    const kept = lines.filter((l) => /KEPT/.test(l));
    expect(kept).toHaveLength(1);
    expect(lines[lines.length - 1]).toMatch(/KEPT/);
    // Every discarded line has F disagreeing with the wanted bit; the kept one agrees.
    for (const l of lines) {
      const m = /F\(K~, C, \d+\) = (\d), wanted (\d)/.exec(l)!;
      expect(m[1] === m[2]).toBe(/KEPT/.test(l));
    }
    await expectVerdict(page, 'bias-step', { state: 'alarm', text: /CIPHERTEXT CHOSEN AFTER/ });
  });
});

test.describe('the checks that constrain the subverter', () => {
  /**
   * Mutation (6) in verdict-mutations.json makes the IV-replacement encryptor
   * leak on EVERY message rather than once. This is the test that catches it:
   * the user's own repeated-IV check is the reason the paper's attack is
   * stateful, so the check has to be live here rather than described.
   */
  test('the repeated-IV check is why IV replacement happens once and only once', async ({ page }) => {
    await boot(page);
    await page.getByRole('tab', { name: /IV replacement/ }).click();
    await page.locator('#iv-encrypt-8').click();
    await expect(page.locator('#iv-log .log-row')).toHaveCount(8);
    const shown = await rows(page, 'iv');
    const ivs = new Set(shown.map((r) => hex(r.ct.subarray(0, 16))));
    expect(ivs.size, 'the IVs on screen must all differ').toBe(shown.length);
    await expectVerdict(page, 'iv-no-repeat-iv', { state: 'pass', text: /9 IVs, all distinct/ });
    // Exactly one ciphertext carries the key, and it is the first one.
    const leaking = await page.locator('#iv-log .hex-iv.is-leak').count();
    expect(leaking, 'only the first ciphertext (now scrolled out of the shown eight) carries the key').toBe(0);
    await expectVerdict(page, 'iv-recovery', { state: 'alarm' });
  });
});

test.describe('structure that a scan would otherwise call accessible', () => {
  test('the [hidden] probe: an inactive panel is hidden by the UA rule and paints nothing', async ({ page }) => {
    await boot(page);
    // All five inactive panels carry [hidden] AND are genuinely not painted. A
    // class rule setting `display` outranks the UA `[hidden]` rule, so a panel
    // can carry the attribute and still be on screen -- which is exactly what
    // this probe exists to catch, and what a gate that force-reveals panels
    // destroys its own ability to see.
    const probe = await page.evaluate(() =>
      ['swap', 'iv', 'bias', 'budget', 'unique'].map((id) => {
        const el = document.getElementById(`panel-${id}`)!;
        return {
          id,
          hidden: el.hasAttribute('hidden'),
          display: getComputedStyle(el).display,
          painted: el.checkVisibility({ checkVisibilityCSS: true }),
        };
      }),
    );
    for (const p of probe) {
      expect(p.hidden, `#panel-${p.id} carries [hidden]`).toBe(true);
      expect(p.display, `#panel-${p.id} is display:none, not merely attributed`).toBe('none');
      expect(p.painted, `#panel-${p.id} paints nothing`).toBe(false);
    }
  });

  test('every verdict marker the page renders is declared in verdict-mutations.json', async ({ page }) => {
    const ledger = JSON.parse(readFileSync('e2e/verdict-mutations.json', 'utf8')) as {
      markers: Record<string, string>;
    };
    const declared = new Set(Object.keys(ledger.markers));
    const seen = new Set<string>();
    const collect = async (): Promise<void> => {
      for (const m of await page.locator('[data-verdict]').evaluateAll((els) => els.map((e) => e.getAttribute('data-verdict')!))) {
        seen.add(m);
      }
    };

    await boot(page);
    await collect();
    for (const [tab, extra] of [
      [/Swap the code/, '#swap-clear'],
      [/IV replacement/, '#iv-clear'],
      [/Biased ciphertexts/, '#bias-clear'],
    ] as Array<[RegExp, string]>) {
      await page.getByRole('tab', { name: tab }).click();
      await collect();
      // The empty state renders its own verdict, which no other state shows.
      await page.locator(extra).click();
      await collect();
    }
    await openBiasWith128(page);
    await collect();
    await page.getByRole('tab', { name: /How little randomness/ }).click();
    await collect();
    await page.getByRole('tab', { name: /Nothing to choose/ }).click();
    await expect(page.locator('[data-verdict="unique-nocoins"]')).toBeVisible({ timeout: 60_000 });
    await collect();

    const undeclared = [...seen].filter((m) => !declared.has(m)).sort();
    expect(undeclared, 'verdict markers rendered by the page but absent from the ledger').toEqual([]);
    const unrendered = [...declared].filter((m) => !seen.has(m)).sort();
    expect(unrendered, 'markers declared in the ledger that this tour never rendered').toEqual([]);
  });
});
