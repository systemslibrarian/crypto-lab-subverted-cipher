/**
 * AES-128, one block in each direction (FIPS 197).
 *
 * WebCrypto has AES-CTR, AES-CBC and AES-GCM but no raw single-block call, and
 * this lab needs one in BOTH directions: the IV-replacement subversion sets
 * IV = E(K~, K) and its holder recovers K = E^-1(K~, IV) (paper section 4.1).
 * The brief offers two honest routes; this is route (a), a small table-based
 * AES that passes FIPS 197 Appendix C.1 both ways. Route (b) -- WebCrypto
 * AES-CBC under a zero IV -- is used by the tests as an INDEPENDENT
 * cross-check of this code on random blocks, so a bug here cannot agree with
 * itself.
 *
 * The S-box is generated at load from GF(2^8) arithmetic rather than pasted
 * as 256 literals, so the table is derived from the field, not trusted.
 */

const SBOX = new Uint8Array(256);
const INV_SBOX = new Uint8Array(256);
{
  const rotl8 = (x: number, s: number): number => ((x << s) | (x >>> (8 - s))) & 0xff;
  let p = 1;
  let q = 1;
  do {
    // p <- p * 3 in GF(2^8), q <- q / 3: together they walk every nonzero
    // element as (x, x^-1) pairs.
    p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1b : 0)) & 0xff;
    q = (q ^ (q << 1)) & 0xff;
    q = (q ^ (q << 2)) & 0xff;
    q = (q ^ (q << 4)) & 0xff;
    if (q & 0x80) q ^= 0x09;
    const affine = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);
    SBOX[p] = (affine ^ 0x63) & 0xff;
  } while (p !== 1);
  SBOX[0] = 0x63; // zero has no inverse; the affine constant alone
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]!] = i;
}

/** Multiply by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1. */
const xtime = (b: number): number => ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff;

function gmul(a: number, b: number): number {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a = xtime(a);
    b >>>= 1;
  }
  return r;
}

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

export const BLOCK_BYTES = 16;
export const KEY_BYTES = 16;

export class Aes128 {
  /** Eleven round keys, 16 bytes each, laid out as FIPS 197 section 5.2 expands them. */
  private readonly roundKeys: Uint8Array;

  constructor(key: Uint8Array) {
    if (key.length !== KEY_BYTES) throw new Error(`AES-128 needs a 16-byte key, got ${key.length}`);
    const w = new Uint8Array(176);
    w.set(key);
    for (let i = 16; i < 176; i += 4) {
      let t0 = w[i - 4]!;
      let t1 = w[i - 3]!;
      let t2 = w[i - 2]!;
      let t3 = w[i - 1]!;
      if (i % 16 === 0) {
        // RotWord, SubWord, Rcon
        const r = RCON[i / 16 - 1]!;
        [t0, t1, t2, t3] = [SBOX[t1]! ^ r, SBOX[t2]!, SBOX[t3]!, SBOX[t0]!];
      }
      w[i] = w[i - 16]! ^ t0;
      w[i + 1] = w[i - 15]! ^ t1;
      w[i + 2] = w[i - 14]! ^ t2;
      w[i + 3] = w[i - 13]! ^ t3;
    }
    this.roundKeys = w;
  }

  private addRoundKey(s: Uint8Array, round: number): void {
    const off = round * 16;
    for (let i = 0; i < 16; i++) s[i]! ^= this.roundKeys[off + i]!;
  }

  encryptBlock(input: Uint8Array): Uint8Array {
    if (input.length !== BLOCK_BYTES) throw new Error(`block must be 16 bytes, got ${input.length}`);
    // State is column-major: byte i sits at row i % 4, column floor(i / 4).
    const s = Uint8Array.from(input);
    this.addRoundKey(s, 0);
    for (let round = 1; round <= 10; round++) {
      // SubBytes
      for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]!]!;
      // ShiftRows: row r rotates left by r
      for (let r = 1; r < 4; r++) {
        const row = [s[r]!, s[r + 4]!, s[r + 8]!, s[r + 12]!];
        for (let c = 0; c < 4; c++) s[r + 4 * c] = row[(c + r) % 4]!;
      }
      // MixColumns (skipped in the final round)
      if (round !== 10) {
        for (let c = 0; c < 4; c++) {
          const a0 = s[4 * c]!;
          const a1 = s[4 * c + 1]!;
          const a2 = s[4 * c + 2]!;
          const a3 = s[4 * c + 3]!;
          s[4 * c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
          s[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
          s[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
          s[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        }
      }
      this.addRoundKey(s, round);
    }
    return s;
  }

  decryptBlock(input: Uint8Array): Uint8Array {
    if (input.length !== BLOCK_BYTES) throw new Error(`block must be 16 bytes, got ${input.length}`);
    const s = Uint8Array.from(input);
    this.addRoundKey(s, 10);
    for (let round = 9; round >= 0; round--) {
      // InvShiftRows: row r rotates right by r
      for (let r = 1; r < 4; r++) {
        const row = [s[r]!, s[r + 4]!, s[r + 8]!, s[r + 12]!];
        for (let c = 0; c < 4; c++) s[r + 4 * c] = row[(c - r + 4) % 4]!;
      }
      // InvSubBytes
      for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]!]!;
      this.addRoundKey(s, round);
      // InvMixColumns (skipped before the first round key, i.e. after round 0)
      if (round !== 0) {
        for (let c = 0; c < 4; c++) {
          const a0 = s[4 * c]!;
          const a1 = s[4 * c + 1]!;
          const a2 = s[4 * c + 2]!;
          const a3 = s[4 * c + 3]!;
          s[4 * c] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
          s[4 * c + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
          s[4 * c + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
          s[4 * c + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
        }
      }
    }
    return s;
  }
}

/** E(K, B): one block forward. */
export function encryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  return new Aes128(key).encryptBlock(block);
}

/** E^-1(K, C): one block backward. */
export function decryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  return new Aes128(key).decryptBlock(block);
}
