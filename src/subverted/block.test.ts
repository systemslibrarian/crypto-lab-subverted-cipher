import { describe, expect, it } from 'vitest';
import { Aes128, decryptBlock, encryptBlock } from './block.js';
import { hex, randomBytes } from './bytes.js';
import { FIPS197_C1 } from './vectors.js';

/**
 * Check A, the block cipher. The FIPS 197 Appendix C.1 vector in both
 * directions, then an INDEPENDENT cross-check against WebCrypto by the
 * brief's route (b): E_K(B) is the first block of CBC-encrypting B under a
 * zero IV, and D_K(c) is CBC-decrypting c || x under a zero IV where x is the
 * one block CBC-encrypting the empty message under IV = c produces. A bug in
 * block.ts cannot agree with WebCrypto by accident on 64 random blocks.
 */

const ZERO_IV = new Uint8Array(16);

async function webcryptoEncryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO_IV }, k, block as BufferSource));
  return out.subarray(0, 16);
}

async function webcryptoDecryptBlock(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  const enc = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['encrypt']);
  const dec = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CBC', false, ['decrypt']);
  const x = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: block as BufferSource }, enc, new Uint8Array()));
  expect(x.length).toBe(16);
  const joined = new Uint8Array(32);
  joined.set(block);
  joined.set(x, 16);
  const out = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ZERO_IV }, dec, joined));
  expect(out.length).toBe(16);
  return out;
}

describe('AES-128 single block (FIPS 197)', () => {
  it('Appendix C.1 encrypts 00112233...eeff to 69c4e0d8...c55a', () => {
    expect(hex(encryptBlock(FIPS197_C1.key, FIPS197_C1.plaintext))).toBe(hex(FIPS197_C1.ciphertext));
  });

  it('Appendix C.1 decrypts 69c4e0d8...c55a back to 00112233...eeff', () => {
    expect(hex(decryptBlock(FIPS197_C1.key, FIPS197_C1.ciphertext))).toBe(hex(FIPS197_C1.plaintext));
  });

  it('agrees with WebCrypto AES-CBC (route b) forward on 64 random blocks', async () => {
    for (let i = 0; i < 64; i++) {
      const key = randomBytes(16);
      const block = randomBytes(16);
      expect(hex(encryptBlock(key, block))).toBe(hex(await webcryptoEncryptBlock(key, block)));
    }
  });

  it('agrees with WebCrypto AES-CBC (route b) backward on 64 random blocks', async () => {
    for (let i = 0; i < 64; i++) {
      const key = randomBytes(16);
      const block = randomBytes(16);
      expect(hex(decryptBlock(key, block))).toBe(hex(await webcryptoDecryptBlock(key, block)));
    }
  });

  it('decrypt inverts encrypt for 256 random (key, block) pairs', () => {
    for (let i = 0; i < 256; i++) {
      const aes = new Aes128(randomBytes(16));
      const block = randomBytes(16);
      expect(hex(aes.decryptBlock(aes.encryptBlock(block)))).toBe(hex(block));
    }
  });

  it('rejects keys and blocks of the wrong length', () => {
    expect(() => new Aes128(new Uint8Array(15))).toThrow(/16-byte key/);
    expect(() => new Aes128(new Uint8Array(32))).toThrow(/16-byte key/);
    expect(() => encryptBlock(new Uint8Array(16), new Uint8Array(15))).toThrow(/16 bytes/);
    expect(() => decryptBlock(new Uint8Array(16), new Uint8Array(17))).toThrow(/16 bytes/);
  });
});
