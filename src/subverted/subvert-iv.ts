/**
 * IV replacement -- the paper's section 4.1 "stateful attack", verbatim:
 *
 *     E~(K~, K, M, A, sigma, i)
 *       If sigma = 0 then IV <- E(K~, K)      -- one block-cipher call
 *       Else IV <- {0,1}^n                      -- honest randomness
 *       C <- E(K, M, A; IV);  sigma <- sigma + 1;  return C
 *
 * On the FIRST encryption only, the IV is the user's key enciphered under the
 * subversion key. The holder of K~ reads the first 16 bytes of the first
 * ciphertext and computes K = E^-1(K~, IV) (see bigbrother.ts). Every later
 * IV is random, which is why the subversion needs state: a repeated IV would
 * be visible to anyone, and the user's own "no repeated IVs" check (tests.ts)
 * is exactly what would catch a version that did this every time -- the
 * brief's mutation (6).
 *
 * The paper assumes key and IV have the same length; with AES-128 keys and
 * 16-byte IVs they do, so the whole key fits in one IV.
 */
import { Aes128, KEY_BYTES } from './block.js';
import { randomBytes } from './bytes.js';
import { encryptWithIv, IV_BYTES } from './ctr.js';
import type { Subversion } from './types.js';

export interface IvReplacementResult {
  readonly ct: Uint8Array;
  /** True for the one ciphertext whose IV carries the key. */
  readonly leaked: boolean;
  /** The subverter's counter before this call (the paper's sigma). */
  readonly sigma: number;
}

export class IvReplacementEncryptor implements Subversion<IvReplacementResult> {
  readonly name = 'IV replacement (section 4.1)';
  private sigma = 0;
  private readonly cipher: Aes128;

  /**
   * @param subKey  K~, a 16-byte AES key held by the subverter.
   * @param coins   where the LATER IVs come from; the CSPRNG unless a test injects one.
   */
  constructor(
    subKey: Uint8Array,
    private readonly coins: () => Uint8Array = () => randomBytes(IV_BYTES),
  ) {
    if (subKey.length !== KEY_BYTES) throw new Error(`subversion key must be ${KEY_BYTES} bytes`);
    this.cipher = new Aes128(subKey);
  }

  async encrypt(userKey: Uint8Array, msg: Uint8Array): Promise<IvReplacementResult> {
    if (userKey.length !== KEY_BYTES) throw new Error(`user key must be ${KEY_BYTES} bytes`);
    const sigma = this.sigma;
    const leaked = sigma === 0;
    const iv = leaked ? this.cipher.encryptBlock(userKey) : this.coins();
    this.sigma = sigma + 1;
    return { ct: encryptWithIv(userKey, iv, msg), leaked, sigma };
  }

  /** A system reset: the paper notes this is what makes the attack detectable (a repeated IV). */
  reset(): void {
    this.sigma = 0;
  }

  get state(): number {
    return this.sigma;
  }
}
