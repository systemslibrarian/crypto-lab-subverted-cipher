/**
 * Exhibit 6: a scheme with nothing to choose.
 *
 * This follows the paper's section 5 construction "surveillance-resistance
 * from nonce-based schemes" (Theorem 6): take any nonce-based AEAD Pi that is
 * NON-DEGENERATE -- for every key, message, associated data and nonce there is
 * at most one ciphertext the decryptor accepts as that message -- and make it
 * stateful by using a counter as the nonce on both sides:
 *
 *     E*(K, M, A, sigma)  =  (E(K, M, A, sigma),  sigma + 1)
 *     D*(K, C, A, tau)    =  (D(K, C, A, tau),    tau + 1)
 *
 * The result is deterministic, stateful, and has UNIQUE CIPHERTEXTS; by
 * Theorem 4 any subversion of it that keeps decryption correct has advantage
 * zero, because the subverted code is forced to output the one ciphertext
 * the honest code would have. The paper names OCB and modes from [40, 41]
 * as non-degenerate; this lab instantiates Pi with AES-GCM (NIST SP 800-38D,
 * through WebCrypto), with a 96-bit nonce that is the counter as a 12-byte
 * big-endian integer and a 128-bit tag.
 *
 * Why AES-GCM is non-degenerate: for a fixed key and nonce the CTR keystream
 * is fixed, so the ciphertext body that decrypts to M is exactly M XOR
 * keystream, and the tag is a deterministic function (GHASH, then one more
 * block-cipher call) of the key, nonce, associated data and that body. Any
 * other body decrypts to a different message; any other tag is rejected.
 * So the set C_Pi(K, M, A, N) has exactly one element. (The paper's second
 * construction, encode-then-encipher with a variable-input-length PRP,
 * Theorem 5, is not built here.)
 *
 * The decryptor's own counter is the only nonce it will try. A ciphertext
 * that arrives out of order -- the decryptor's state out of step with the
 * encryptor's -- is a ciphertext under the wrong nonce, and GCM rejects it.
 * On rejection the paper's D* returns (bottom, tau): the state does not move.
 */
import type { BaseScheme } from './types.js';

export const NONCE_BYTES = 12;
export const TAG_BITS = 128;
export const GCM_KEY_BYTES = 16;

/** The counter as a 96-bit big-endian nonce. */
export function nonceFromCounter(counter: number): Uint8Array {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError(`counter ${counter}`);
  const n = new Uint8Array(NONCE_BYTES);
  let v = BigInt(counter);
  for (let i = NONCE_BYTES - 1; i >= 0; i--) {
    n[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return n;
}

async function gcmKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  if (key.length !== GCM_KEY_BYTES) throw new Error(`AES-128-GCM needs a 16-byte key, got ${key.length}`);
  return crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, [usage]);
}

/** Raw AES-GCM: body || tag. Used by the KAT tests and by the stateful wrapper below. */
export async function gcmEncrypt(key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource, tagLength: TAG_BITS },
    await gcmKey(key, 'encrypt'),
    msg as BufferSource,
  );
  return new Uint8Array(out);
}

/** Raw AES-GCM decryption; null on any authentication failure. */
export async function gcmDecrypt(key: Uint8Array, nonce: Uint8Array, ad: Uint8Array, ct: Uint8Array): Promise<Uint8Array | null> {
  try {
    const out = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: ad as BufferSource, tagLength: TAG_BITS },
      await gcmKey(key, 'decrypt'),
      ct as BufferSource,
    );
    return new Uint8Array(out);
  } catch {
    return null;
  }
}

export interface UniqueCiphertext {
  readonly ct: Uint8Array;
  /** The nonce the encryptor used: its counter, which the receiver must also hold. */
  readonly nonce: Uint8Array;
  readonly counter: number;
}

/** E*: the sender's half, with its counter sigma. */
export class UniqueEncryptor {
  private sigma = 0;
  constructor(private readonly key: Uint8Array) {}

  async encrypt(msg: Uint8Array, ad: Uint8Array = new Uint8Array()): Promise<UniqueCiphertext> {
    const counter = this.sigma;
    const nonce = nonceFromCounter(counter);
    const ct = await gcmEncrypt(this.key, nonce, ad, msg);
    this.sigma = counter + 1;
    return { ct, nonce, counter };
  }

  get state(): number {
    return this.sigma;
  }

  reset(): void {
    this.sigma = 0;
  }

  /** Put the sender at a chosen counter (the tests compare two senders at one random state). */
  seek(counter: number): void {
    if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError(`counter ${counter}`);
    this.sigma = counter;
  }
}

export type UniqueDecryption =
  | { readonly ok: true; readonly msg: Uint8Array; readonly counter: number }
  | { readonly ok: false; readonly reason: 'rejected'; readonly counter: number };

/** D*: the receiver's half, with its counter tau. Rejection leaves tau where it was. */
export class UniqueDecryptor {
  private tau = 0;
  constructor(private readonly key: Uint8Array) {}

  async decrypt(ct: Uint8Array, ad: Uint8Array = new Uint8Array()): Promise<UniqueDecryption> {
    const counter = this.tau;
    const msg = await gcmDecrypt(this.key, nonceFromCounter(counter), ad, ct);
    if (msg === null) return { ok: false, reason: 'rejected', counter };
    this.tau = counter + 1;
    return { ok: true, msg, counter };
  }

  get state(): number {
    return this.tau;
  }

  /** Put the receiver at a chosen counter -- how the page shows "state out of step". */
  seek(counter: number): void {
    if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError(`counter ${counter}`);
    this.tau = counter;
  }
}

/**
 * The scheme as the biased-ciphertext subverter sees it: zero coin bytes.
 * Handing this to `BiasedEncryptor` makes it report "no coins to choose"
 * (brief check F), which is Theorem 4 in one line.
 */
export function uniqueAsBaseScheme(encryptor: UniqueEncryptor, ad: Uint8Array = new Uint8Array()): BaseScheme {
  return {
    name: 'AES-GCM with a counter nonce (unique ciphertexts)',
    coinBytes: 0,
    async encrypt(_key, msg) {
      return (await encryptor.encrypt(msg, ad)).ct;
    },
  };
}
