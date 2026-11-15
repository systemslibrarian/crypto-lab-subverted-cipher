import { describe, expect, it } from 'vitest';
import { be32, concat, fromHex, hex, utf8 } from './bytes.js';
import { F, hmacSha256, keyBit, setKeyBit } from './prf.js';
import { RFC4231 } from './vectors.js';

/** Check A, the PRF: RFC 4231 vectors, then the brief's FACTS 5 conventions pinned one at a time. */
describe('HMAC-SHA-256 and the one-bit PRF F', () => {
  for (const v of RFC4231) {
    it(`RFC 4231 ${v.name}`, async () => {
      expect(hex(await hmacSha256(v.key, v.data))).toBe(hex(v.tag));
    });
  }

  it('RFC 4231 case 2 (key "Jefe") begins 5bdcc146bf60754e', async () => {
    const tag = await hmacSha256(utf8('Jefe'), utf8('what do ya want for nothing?'));
    expect(hex(tag).startsWith('5bdcc146bf60754e')).toBe(true);
  });

  it('F is the LEAST significant bit of the FIRST byte of HMAC(K~, C || j), j as 4 big-endian bytes from 0', async () => {
    const subKey = fromHex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
    const ct = fromHex('50fe67cc996d32b6da0937e99bafec60d6e0b8f4');
    for (const j of [0, 1, 127, 128, 65535, 70000]) {
      const mac = await hmacSha256(subKey, concat(ct, be32(j)));
      expect(await F(subKey, ct, j)).toBe(mac[0]! & 1);
      // The encoding of j is four bytes, and the whole four bytes matter.
      const oneByte = await hmacSha256(subKey, concat(ct, new Uint8Array([j & 0xff])));
      expect(hex(oneByte)).not.toBe(hex(mac));
    }
  });

  it('be32 is big-endian and refuses out-of-range values', () => {
    expect(hex(be32(0))).toBe('00000000');
    expect(hex(be32(127))).toBe('0000007f');
    expect(hex(be32(0x01020304))).toBe('01020304');
    expect(() => be32(-1)).toThrow(RangeError);
    expect(() => be32(2 ** 32)).toThrow(RangeError);
  });

  it('key bits are read most significant bit first: (K[j >> 3] >> (7 - (j & 7))) & 1', () => {
    const key = fromHex('80000000000000000000000000000001');
    expect(keyBit(key, 0)).toBe(1);
    expect(keyBit(key, 1)).toBe(0);
    expect(keyBit(key, 7)).toBe(0);
    expect(keyBit(key, 127)).toBe(1);
    expect(keyBit(key, 120)).toBe(0);
    const k2 = fromHex('000102030405060708090a0b0c0d0e0f');
    // byte 1 = 0x01: its bit 7 (j = 15) is 1, its bit 0 (j = 8) is 0
    expect(keyBit(k2, 15)).toBe(1);
    expect(keyBit(k2, 8)).toBe(0);
    // byte 2 = 0x02: j = 22 is 1
    expect(keyBit(k2, 22)).toBe(1);
    expect(keyBit(k2, 23)).toBe(0);
    expect(() => keyBit(k2, 128)).toThrow(RangeError);
  });

  it('setKeyBit inverts keyBit for every position of a random key', () => {
    const key = fromHex('0f1e2d3c4b5a69788796a5b4c3d2e1f0');
    const rebuilt = new Uint8Array(16);
    for (let j = 0; j < 128; j++) setKeyBit(rebuilt, j, keyBit(key, j));
    expect(hex(rebuilt)).toBe(hex(key));
  });
});
