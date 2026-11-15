/**
 * CTR$: counter mode with a random starting counter (NIST SP 800-38A section
 * 6.5, with the initial counter block chosen at random and sent in the clear).
 *
 *   ciphertext = IV || AES-CTR_K(M)
 *
 * The IV is 16 bytes and is used directly as the first counter block; each
 * later block is the previous one plus one, as a 128-bit big-endian integer
 * with the carry running the whole way (so an IV ending in ff bytes carries
 * into the byte above). This is the base scheme the paper's section 4 attacks
 * apply to: it is randomized, stateless, and it SURFACES its IV -- the first
 * 16 bytes of every ciphertext are the coins the encryptor chose.
 *
 * The mode is written out here rather than taken from WebCrypto's AES-CTR
 * because the IV handling IS the subject: the subverted encryptors below
 * replace or bias exactly these 16 bytes, and the counter increment is one of
 * the things the brief's mutation ledger must be able to break.
 */
import { Aes128, BLOCK_BYTES } from './block.js';
import { randomBytes } from './bytes.js';
import type { BaseScheme } from './types.js';

export const IV_BYTES = 16;

/** Add one to a 16-byte big-endian counter, in place, carrying through all 128 bits. */
export function incrementCounter(block: Uint8Array): void {
  for (let i = BLOCK_BYTES - 1; i >= 0; i--) {
    block[i] = (block[i]! + 1) & 0xff;
    if (block[i] !== 0) break;
  }
}

/** The keystream XOR shared by encryption and decryption. */
function ctrXor(aes: Aes128, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  const counter = Uint8Array.from(iv);
  for (let at = 0; at < data.length; at += BLOCK_BYTES) {
    const ks = aes.encryptBlock(counter);
    const n = Math.min(BLOCK_BYTES, data.length - at);
    for (let i = 0; i < n; i++) out[at + i] = data[at + i]! ^ ks[i]!;
    incrementCounter(counter);
  }
  return out;
}

/** Encrypt under a caller-supplied IV. The honest encryptor passes fresh randomness. */
export function encryptWithIv(key: Uint8Array, iv: Uint8Array, msg: Uint8Array): Uint8Array {
  if (iv.length !== IV_BYTES) throw new Error(`IV must be ${IV_BYTES} bytes, got ${iv.length}`);
  const body = ctrXor(new Aes128(key), iv, msg);
  const out = new Uint8Array(IV_BYTES + body.length);
  out.set(iv);
  out.set(body, IV_BYTES);
  return out;
}

/** The honest encryptor: IV from the platform CSPRNG, then CTR. */
export function encrypt(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return encryptWithIv(key, randomBytes(IV_BYTES), msg);
}

/**
 * The honest decryptor. Returns null for a ciphertext shorter than one IV;
 * an empty message is legitimate and decrypts from a 16-byte ciphertext.
 */
export function decrypt(key: Uint8Array, ct: Uint8Array): Uint8Array | null {
  if (ct.length < IV_BYTES) return null;
  return ctrXor(new Aes128(key), ct.subarray(0, IV_BYTES), ct.subarray(IV_BYTES));
}

export const ivOf = (ct: Uint8Array): Uint8Array => ct.subarray(0, IV_BYTES);

/** CTR$ as a `BaseScheme`: 16 bytes of coins per message, all of them the IV. */
export const CTR_DOLLAR: BaseScheme = {
  name: 'CTR$ (AES-128, random 16-byte IV)',
  coinBytes: IV_BYTES,
  async encrypt(key, msg, coins) {
    return encryptWithIv(key, coins ?? randomBytes(IV_BYTES), msg);
  },
};
