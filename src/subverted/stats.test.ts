import { describe, expect, it } from 'vitest';
import { extractKeyBits } from './bigbrother.js';
import { randomBytes } from './bytes.js';
import { encrypt } from './ctr.js';
import { keyBit } from './prf.js';
import { BiasedEncryptor, budgetCoins } from './subvert-bias.js';

/**
 * Check E: the statistics, counted from real runs with fresh platform
 * randomness. Every number here is what the brief's own measurement found
 * (mean 2.01 over 38,400; 0.2465 / 0.0576 / 0.0034 over 20,000 each; about
 * half right on honest ciphertexts). The tolerances are the brief's, and each
 * is at least six standard deviations wide, so a failure here is a defect and
 * not noise. Tagged [slow]; they run in every CI run.
 */
describe('Check E: statistics of the biased-ciphertext subverter', () => {
  it('[slow] over 10,000 subverted ciphertexts with random coins, the mean candidates tried is between 1.9 and 2.1', async () => {
    const sub = new BiasedEncryptor(randomBytes(32));
    const key = randomBytes(16);
    let total = 0;
    let largest = 0;
    const N = 10_000;
    for (let i = 0; i < N; i++) {
      const r = await sub.encrypt(key, randomBytes(8));
      expect(r.ok).toBe(true);
      total += r.tried;
      largest = Math.max(largest, r.tried);
    }
    const mean = total / N;
    expect(mean).toBeGreaterThan(1.9);
    expect(mean).toBeLessThan(2.1);
    // Geometric(1/2): a run above 30 in 10,000 draws is a one-in-a-hundred-million event.
    expect(largest).toBeLessThan(31);
  });

  const budgets: Array<{ c: number; expected: number; tolerance: number }> = [
    { c: 1, expected: 0.25, tolerance: 0.02 },
    { c: 2, expected: 0.0625, tolerance: 0.01 },
    { c: 3, expected: 0.0039, tolerance: 0.003 },
  ];
  for (const { c, expected, tolerance } of budgets) {
    it(`[slow] with a ${c}-bit coin budget the subverter fails with rate 2^-(2^${c}) = ${expected} +/- ${tolerance} over 20,000 trials`, async () => {
      const sub = new BiasedEncryptor(randomBytes(32), undefined, budgetCoins(c), c);
      const key = randomBytes(16);
      let failures = 0;
      const N = 20_000;
      for (let i = 0; i < N; i++) {
        const r = await sub.encrypt(key, randomBytes(4));
        if (!r.ok) {
          expect(r.reason).toBe('no suitable coin');
          failures++;
        }
      }
      const rate = failures / N;
      expect(rate).toBeGreaterThan(expected - tolerance);
      expect(rate).toBeLessThan(expected + tolerance);
    });
  }

  it('[slow] honest-ciphertext control over 100 fresh keys: extraction gets between 60 and 68 of 128 bits right on average', async () => {
    const subKey = randomBytes(32);
    let totalRight = 0;
    for (let k = 0; k < 100; k++) {
      const key = randomBytes(16);
      const cts: Uint8Array[] = [];
      for (let j = 0; j < 128; j++) cts.push(encrypt(key, randomBytes(6)));
      const x = await extractKeyBits(subKey, cts);
      let right = 0;
      for (let j = 0; j < 128; j++) if (x.bits[j] === keyBit(key, j)) right++;
      totalRight += right;
    }
    const mean = totalRight / 100;
    expect(mean).toBeGreaterThan(60);
    expect(mean).toBeLessThan(68);
  });
});
