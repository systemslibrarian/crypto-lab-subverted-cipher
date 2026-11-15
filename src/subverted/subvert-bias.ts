/**
 * Biased ciphertexts -- the paper's section 4.2, the "universal" attack:
 *
 *     E~(K~, K, M, A, sigma, i)
 *       j <- sigma mod |K|
 *       draw coins delta until F(K~, C || j || i) = K[j], where C = E(K, M, A; delta)
 *       sigma <- sigma + 1;  return C
 *
 * The subverted code keeps a counter j. For the j-th ciphertext it keeps
 * drawing fresh coins (here: candidate IVs) and encrypting until the one-bit
 * PRF F, evaluated on the resulting ciphertext, equals bit j of the user's
 * key. Each ciphertext is a perfectly ordinary CTR$ ciphertext under the
 * user's key -- it decrypts correctly, and its IV is one of the uniformly
 * random candidates -- but which candidate was kept is correlated with one
 * key bit, through F, which nobody without K~ can evaluate. After |K| = 128
 * ciphertexts the whole key has gone out, whatever the messages were.
 *
 * Expected candidates per ciphertext: geometric with mean 2 (each candidate
 * matches the target bit with probability 1/2). With only c bits of coins the
 * subverter has 2^c candidates and fails to find one with probability
 * 2^-(2^c) -- the paper's remark that about 7 bits of randomness suffice
 * (2^-128). That failure is REPORTED here, never papered over: a ciphertext
 * with the wrong bit is not emitted and called a success (brief, EDGE CASES).
 *
 * The paper's F also takes a user index i; this lab has one user and omits it.
 */
import { randomBytes } from './bytes.js';
import { CTR_DOLLAR } from './ctr.js';
import { F, keyBit } from './prf.js';
import type { BaseScheme, CoinSource, Subversion } from './types.js';

export type BiasResult =
  | {
      readonly ok: true;
      readonly ct: Uint8Array;
      /** Which key bit this ciphertext carries. */
      readonly j: number;
      /** How many candidates were encrypted before one satisfied F. */
      readonly tried: number;
    }
  | {
      readonly ok: false;
      readonly reason: 'no suitable coin' | 'no coins to choose';
      readonly j: number;
      readonly tried: number;
      /** For 'no coins to choose': the one ciphertext the scheme allows, carrying nothing on purpose. */
      readonly ct?: Uint8Array;
    };

export const SUBVERSION_KEY_BYTES = 32;

/** Fresh platform randomness for every candidate: the normal coin source. */
export const randomCoins = (coinBytes: number): CoinSource => ({
  next: () => randomBytes(coinBytes),
});

export interface Candidate {
  readonly t: number;
  readonly coins: Uint8Array;
  readonly ct: Uint8Array;
  /** F(K~, C, j) on the ciphertext those coins produced. */
  readonly fBit: 0 | 1;
  /** Bit j of the user's key: what the subverter is trying to make F say. */
  readonly target: 0 | 1;
  readonly accepted: boolean;
}

/**
 * Draw candidate `t` for ciphertext `j` and judge it. The encryptor below is
 * nothing but a loop over this function, so the page's step-by-step view
 * (exhibit 4) shows the real decision rather than a second implementation of
 * it.
 */
export async function drawCandidate(
  subKey: Uint8Array,
  scheme: BaseScheme,
  userKey: Uint8Array,
  msg: Uint8Array,
  j: number,
  coins: CoinSource,
  t: number,
): Promise<Candidate> {
  const drawn = await coins.next(j, t);
  const ct = await scheme.encrypt(userKey, msg, drawn);
  const fBit = await F(subKey, ct, j);
  const target = keyBit(userKey, j);
  return { t, coins: drawn, ct, fBit, target, accepted: fBit === target };
}

export class BiasedEncryptor implements Subversion<BiasResult> {
  readonly name = 'Biased ciphertexts (section 4.2)';
  private sigma = 0;
  private readonly coins: CoinSource;

  /**
   * @param subKey      K~, 32 bytes, the HMAC key behind F.
   * @param scheme      the base scheme being subverted (CTR$ unless exhibit 6 passes its own).
   * @param coins       candidate-coin source; the CSPRNG unless a test or exhibit 5 injects one.
   * @param budgetBits  if set, only 2^budgetBits candidates exist (exhibit 5's coin budget).
   */
  constructor(
    private readonly subKey: Uint8Array,
    private readonly scheme: BaseScheme = CTR_DOLLAR,
    coins?: CoinSource,
    private readonly budgetBits?: number,
  ) {
    if (subKey.length !== SUBVERSION_KEY_BYTES) {
      throw new Error(`subversion key must be ${SUBVERSION_KEY_BYTES} bytes`);
    }
    if (budgetBits !== undefined && (!Number.isInteger(budgetBits) || budgetBits < 0 || budgetBits > 16)) {
      throw new RangeError(`coin budget must be 0..16 bits, got ${budgetBits}`);
    }
    this.coins = coins ?? randomCoins(scheme.coinBytes);
  }

  async encrypt(userKey: Uint8Array, msg: Uint8Array): Promise<BiasResult> {
    const bits = userKey.length * 8;
    const j = this.sigma % bits;
    this.sigma += 1;

    if (this.scheme.coinBytes === 0) {
      // Exhibit 6: a unique-ciphertext scheme offers exactly one ciphertext per
      // (key, message, state). There is no set of coins to draw from, so there
      // is nothing for F to select. The subverter can only emit the honest
      // output; whether F happens to equal K[j] on it is a coin toss it did
      // not get to influence.
      const ct = await this.scheme.encrypt(userKey, msg);
      return { ok: false, reason: 'no coins to choose', j, tried: 1, ct };
    }

    const limit = this.budgetBits === undefined ? Infinity : 2 ** this.budgetBits;
    for (let t = 0; t < limit; t++) {
      const candidate = await drawCandidate(this.subKey, this.scheme, userKey, msg, j, this.coins, t);
      if (candidate.accepted) return { ok: true, ct: candidate.ct, j, tried: t + 1 };
    }
    return { ok: false, reason: 'no suitable coin', j, tried: limit };
  }

  reset(): void {
    this.sigma = 0;
  }

  get state(): number {
    return this.sigma;
  }
}

/**
 * Exhibit 5's coin source: a fresh random IV whose low `bits` bits are the
 * candidate index, so the subverter has exactly 2^bits distinct candidates --
 * coin-injective, as the paper's undetectability proof needs, and nothing
 * else about the IV is under its control.
 */
export function budgetCoins(bits: number, baseSource: () => Uint8Array = () => randomBytes(16)): CoinSource {
  if (bits < 0 || bits > 8) throw new RangeError('budget source supports 0..8 bits in the last byte');
  const mask = (1 << bits) - 1;
  let base = baseSource();
  return {
    next(_j, t) {
      if (t > mask) throw new RangeError(`candidate ${t} exceeds a ${bits}-bit budget`);
      // A new message gets a new random base; only its low `bits` bits are the subverter's to pick.
      if (t === 0) base = baseSource();
      const iv = Uint8Array.from(base);
      iv[15] = (base[15]! & ~mask & 0xff) | t;
      return iv;
    },
  };
}
