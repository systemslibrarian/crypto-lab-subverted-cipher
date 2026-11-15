/**
 * The holder of the subversion key -- extraction ONLY.
 *
 * Brief invariant 3: this side receives ciphertexts and K~ and nothing else,
 * enforced by the function signatures below. Nothing here takes the user's
 * key, so nothing here can compare against it; that comparison, and the
 * "key recovered" verdict it gates, live on the page (invariant 2), where
 * both values are on screen.
 *
 * Two recovery algorithms, one per attack, both straight from the paper:
 *
 *   section 4.1   IV <- X(C[1]);  K <- E^-1(K~, IV)
 *   section 4.2   For j = 1..|C|:  K'[j] <- F(K~, C[j] || j-1)
 */
import { decryptBlock, KEY_BYTES } from './block.js';
import { decrypt, ivOf } from './ctr.js';
import { F, setKeyBit } from './prf.js';

/** Section 4.1: the key is the first ciphertext's IV, deciphered under K~. */
export function recoverKeyFromIv(subKey: Uint8Array, firstCt: Uint8Array): Uint8Array | null {
  if (subKey.length !== KEY_BYTES) throw new Error(`subversion key must be ${KEY_BYTES} bytes`);
  if (firstCt.length < 16) return null;
  return decryptBlock(subKey, ivOf(firstCt));
}

export interface Extraction {
  /** One entry per key bit: 0, 1, or null when no ciphertext has leaked it yet. */
  readonly bits: ReadonlyArray<0 | 1 | null>;
  /** How many of the key's bits are known. */
  readonly known: number;
  /** The key, ONLY once every bit is known; null before that. */
  readonly key: Uint8Array | null;
  /** The bit F produced for each ciphertext, in order (also the per-ciphertext evidence). */
  readonly perCiphertext: ReadonlyArray<0 | 1>;
}

/**
 * Section 4.2: read one key bit off each ciphertext. The j-th ciphertext in
 * the list is assumed to be the subverter's j-th output (its counter was j),
 * exactly as the paper's recovery algorithm assumes. Fewer than `keyBits`
 * ciphertexts leaves the remaining bits null and `key` null -- the panel then
 * says the key is not yet recovered (brief, EDGE CASES).
 */
export async function extractKeyBits(subKey: Uint8Array, cts: ReadonlyArray<Uint8Array>, keyBits = 128): Promise<Extraction> {
  const bits: (0 | 1 | null)[] = new Array<0 | 1 | null>(keyBits).fill(null);
  const perCiphertext: (0 | 1)[] = [];
  for (let j = 0; j < cts.length; j++) {
    const bit = await F(subKey, cts[j]!, j % keyBits);
    perCiphertext.push(bit);
    if (j < keyBits) bits[j] = bit;
  }
  const known = bits.filter((b) => b !== null).length;
  let key: Uint8Array | null = null;
  if (known === keyBits) {
    key = new Uint8Array(keyBits / 8);
    for (let j = 0; j < keyBits; j++) setKeyBit(key, j, bits[j] as 0 | 1);
  }
  return { bits, known, key, perCiphertext };
}

/** Once a key is in hand, every ciphertext under it is plaintext to the holder. */
export function decryptAll(recoveredKey: Uint8Array, cts: ReadonlyArray<Uint8Array>): Array<Uint8Array | null> {
  return cts.map((ct) => decrypt(recoveredKey, ct));
}
