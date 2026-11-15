/**
 * The one-bit PRF F and the key-bit convention -- this lab's concrete choices
 * for the paper's section 4.2, fixed by the brief (FACTS 5) and pinned by the
 * check D vector:
 *
 *   F(K~, C, j) = least significant bit of the first byte of
 *                 HMAC-SHA-256(K~, C || j),  j as a 4-byte big-endian integer,
 *                 j counted from 0;
 *   bit j of K   = (K[j >> 3] >> (7 - (j & 7))) & 1, most significant bit first.
 *
 * The paper's F also takes a user index i; this lab has one user and omits it.
 *
 * HMAC-SHA-256 is WebCrypto's (RFC 2104 / FIPS 198-1), checked against the
 * RFC 4231 vectors in prf.test.ts. The key is imported once per distinct key
 * and cached, because the subverter evaluates F on every candidate ciphertext.
 */
import { be32, concat, hex } from './bytes.js';

const keyCache = new Map<string, Promise<CryptoKey>>();

function hmacKey(key: Uint8Array): Promise<CryptoKey> {
  const id = hex(key);
  let k = keyCache.get(id);
  if (!k) {
    k = crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    keyCache.set(id, k);
    if (keyCache.size > 64) keyCache.delete(keyCache.keys().next().value!);
  }
  return k;
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const mac = await crypto.subtle.sign('HMAC', await hmacKey(key), data as BufferSource);
  return new Uint8Array(mac);
}

/** F(K~, C, j): one bit, as the brief defines it. */
export async function F(subKey: Uint8Array, ct: Uint8Array, j: number): Promise<0 | 1> {
  const mac = await hmacSha256(subKey, concat(ct, be32(j)));
  return (mac[0]! & 1) as 0 | 1;
}

/** Bit j of the key, most significant bit of byte 0 first. */
export function keyBit(key: Uint8Array, j: number): 0 | 1 {
  if (j < 0 || j >= key.length * 8) throw new RangeError(`bit ${j} is outside a ${key.length * 8}-bit key`);
  return ((key[j >> 3]! >> (7 - (j & 7))) & 1) as 0 | 1;
}

/** Set bit j (same convention) in a key being rebuilt. */
export function setKeyBit(key: Uint8Array, j: number, bit: 0 | 1): void {
  const mask = 1 << (7 - (j & 7));
  if (bit) key[j >> 3]! |= mask;
  else key[j >> 3]! &= ~mask & 0xff;
}
