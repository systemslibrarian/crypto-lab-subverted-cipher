/**
 * Brief invariant 1: every subverted ciphertext is decrypted by the HONEST
 * decryptor and compared with its plaintext BEFORE it is displayed. The page
 * never appends a record to the user's log without going through here, so a
 * subverted encryptor that broke decryptability could not quietly show up as
 * a ciphertext on screen -- it would be refused, loudly.
 */
import { decrypt } from './ctr.js';
import { equal } from './bytes.js';
import type { Record } from './types.js';

export class DisplayRefused extends Error {
  constructor(detail: string) {
    super(`refused to display a ciphertext that does not decrypt to its message: ${detail}`);
    this.name = 'DisplayRefused';
  }
}

/** The only constructor of a displayable record. Throws rather than returning a lie. */
export function verifiedRecord(key: Uint8Array, msg: Uint8Array, ct: Uint8Array): Record {
  const pt = decrypt(key, ct);
  if (pt === null) throw new DisplayRefused(`ciphertext is ${ct.length} bytes, shorter than one IV`);
  if (!equal(pt, msg)) {
    throw new DisplayRefused(`honest decryption gives ${pt.length} bytes that differ from the ${msg.length}-byte message`);
  }
  return { msg, ct };
}
