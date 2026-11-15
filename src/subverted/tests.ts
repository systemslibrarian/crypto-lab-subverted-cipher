/**
 * The checks a careful user can run on their own ciphertexts, knowing their
 * own key and nothing about any subversion key. Three of them, each of which
 * a subverted encryptor in this lab passes -- that is the lesson, not a
 * weakness of the checks. These checks ILLUSTRATE undetectability; they do
 * not prove it. The proof is the paper's (Theorems 1 and 3) and rests on F
 * being a PRF.
 *
 *   1. Round trip      -- every ciphertext decrypts, under the user's key, to
 *                         the message that was encrypted (the paper's
 *                         decryptability condition, the most basic test).
 *   2. No repeated IV  -- the 16-byte IVs are all distinct. A repeat is what
 *                         a careless IV-replacement subverter would show.
 *   3. IV byte histogram -- the 256-bin histogram of all IV bytes, with a
 *                         chi-square statistic against uniform. Reported as
 *                         inconclusive below 512 bytes (32 IVs), because a
 *                         chi-square over 255 degrees of freedom on fewer
 *                         bytes says nothing either way.
 */
import { equal, hex } from './bytes.js';
import { decrypt, ivOf } from './ctr.js';
import type { Record } from './types.js';

export type CheckState = 'pass' | 'fail' | 'inconclusive';

export interface Check {
  readonly id: 'roundtrip' | 'no-repeat-iv' | 'iv-histogram';
  readonly label: string;
  readonly state: CheckState;
  /** One sentence a reader can act on. */
  readonly summary: string;
}

export function roundTripCheck(key: Uint8Array, records: ReadonlyArray<Record>): Check {
  const label = 'Round trip';
  if (records.length === 0) return { id: 'roundtrip', label, state: 'inconclusive', summary: 'No ciphertexts yet.' };
  let bad = 0;
  for (const r of records) {
    const pt = decrypt(key, r.ct);
    if (pt === null || !equal(pt, r.msg)) bad++;
  }
  return bad === 0
    ? { id: 'roundtrip', label, state: 'pass', summary: `${records.length} of ${records.length} ciphertexts decrypt to their message under your key.` }
    : { id: 'roundtrip', label, state: 'fail', summary: `${bad} of ${records.length} ciphertexts do NOT decrypt to their message.` };
}

export function repeatedIvCheck(cts: ReadonlyArray<Uint8Array>): Check {
  const label = 'No repeated IV';
  if (cts.length === 0) return { id: 'no-repeat-iv', label, state: 'inconclusive', summary: 'No ciphertexts yet.' };
  const seen = new Set<string>();
  let repeats = 0;
  for (const ct of cts) {
    const iv = hex(ivOf(ct));
    if (seen.has(iv)) repeats++;
    else seen.add(iv);
  }
  return repeats === 0
    ? { id: 'no-repeat-iv', label, state: 'pass', summary: `${cts.length} IVs, all distinct.` }
    : { id: 'no-repeat-iv', label, state: 'fail', summary: `${repeats} repeated IV${repeats === 1 ? '' : 's'} among ${cts.length} ciphertexts.` };
}

export interface Histogram {
  readonly counts: Uint32Array;
  readonly n: number;
  readonly chiSquare: number;
  /** Approximate upper-tail p-value (Wilson-Hilferty normal approximation, 255 degrees of freedom). */
  readonly pValue: number;
}

export const HISTOGRAM_MIN_BYTES = 512;

export function ivHistogram(cts: ReadonlyArray<Uint8Array>): Histogram {
  const counts = new Uint32Array(256);
  let n = 0;
  for (const ct of cts) {
    for (const b of ivOf(ct)) {
      counts[b]!++;
      n++;
    }
  }
  const expected = n / 256;
  let chi = 0;
  if (n > 0) for (const c of counts) chi += ((c - expected) * (c - expected)) / expected;
  return { counts, n, chiSquare: chi, pValue: n > 0 ? chiSquareUpperTail(chi, 255) : 1 };
}

/** Upper-tail probability of a chi-square variable: Wilson-Hilferty cube-root normal approximation. */
export function chiSquareUpperTail(x: number, k: number): number {
  const z = (Math.cbrt(x / k) - (1 - 2 / (9 * k))) / Math.sqrt(2 / (9 * k));
  return 0.5 * erfc(z / Math.SQRT2);
}

/** Complementary error function, Abramowitz and Stegun 7.1.26 (absolute error below 1.5e-7). */
function erfc(x: number): number {
  const t = 1 / (1 + 0.3275911 * Math.abs(x));
  const poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
  const y = poly * Math.exp(-x * x);
  return x >= 0 ? y : 2 - y;
}

/**
 * The significance level for the histogram check. 1e-5 rather than the usual
 * 0.001 on purpose: this check runs on every render, and uniform IVs crossing
 * a 0.001 threshold once in a thousand page loads would be a false alarm about
 * the one thing this page is teaching. A genuinely skewed IV source -- the
 * only kind worth naming here -- misses by many orders of magnitude, not by a
 * factor of a hundred.
 */
export const HISTOGRAM_ALPHA = 1e-5;

export function histogramCheck(cts: ReadonlyArray<Uint8Array>): Check {
  const label = 'IV bytes look uniform';
  const h = ivHistogram(cts);
  if (h.n < HISTOGRAM_MIN_BYTES) {
    return {
      id: 'iv-histogram',
      label,
      state: 'inconclusive',
      summary: `${h.n} IV bytes; at least ${HISTOGRAM_MIN_BYTES} are needed before a 256-bin histogram says anything.`,
    };
  }
  const stat = `chi-square ${h.chiSquare.toFixed(1)} over 255 degrees of freedom, p = ${h.pValue.toExponential(2)}`;
  return h.pValue >= HISTOGRAM_ALPHA
    ? { id: 'iv-histogram', label, state: 'pass', summary: `${h.n} IV bytes are unremarkable: ${stat}.` }
    : { id: 'iv-histogram', label, state: 'fail', summary: `${h.n} IV bytes are NOT uniform: ${stat}.` };
}

export function runUserChecks(key: Uint8Array, records: ReadonlyArray<Record>): Check[] {
  const cts = records.map((r) => r.ct);
  return [roundTripCheck(key, records), repeatedIvCheck(cts), histogramCheck(cts)];
}
