import { describe, expect, it } from 'vitest';
import { concat, fromHex, hex, randomBytes, utf8 } from './bytes.js';
import { CTR_DOLLAR, decrypt, encrypt, encryptWithIv, incrementCounter, ivOf } from './ctr.js';
import { NIST_F51 } from './vectors.js';

/**
 * Check A, the mode: NIST SP 800-38A F.5.1 in full, whose counter carries from
 * ...feff into ...ff00 after the first block. Then the carry cases the brief's
 * mutation (8) needs -- an IV of sixteen ff bytes, and one whose LOW 64 bits
 * are all ones -- each with its expected value taken from an INDEPENDENT
 * implementation: WebCrypto's AES-CTR with a 128-bit counter length, which
 * wraps the whole block.
 */

async function webcryptoCtr(key: Uint8Array, iv: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-CTR', false, ['encrypt']);
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv as BufferSource, length: 128 }, k, msg as BufferSource),
  );
}

describe('CTR$ (AES-128 counter mode, random 16-byte IV)', () => {
  it('NIST SP 800-38A F.5.1: four blocks, ciphertext begins 874d6191b620e326 and ends 792170a0f3009cee', () => {
    const ct = encryptWithIv(NIST_F51.key, NIST_F51.counter, NIST_F51.plaintext);
    const body = hex(ct.subarray(16));
    expect(body).toBe(hex(NIST_F51.ciphertext));
    expect(body.startsWith('874d6191b620e326')).toBe(true);
    expect(body.endsWith('792170a0f3009cee')).toBe(true);
  });

  it('NIST SP 800-38A F.5.2 (the same vector decrypted) recovers the plaintext', () => {
    expect(hex(decrypt(NIST_F51.key, concat(NIST_F51.counter, NIST_F51.ciphertext))!)).toBe(hex(NIST_F51.plaintext));
  });

  it('the counter increment carries through all 128 bits', () => {
    const c = fromHex('ffffffffffffffffffffffffffffffff');
    incrementCounter(c);
    expect(hex(c)).toBe('00000000000000000000000000000000');
    const d = fromHex('0000000000000000ffffffffffffffff');
    incrementCounter(d);
    expect(hex(d)).toBe('00000000000000010000000000000000');
    const e = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    incrementCounter(e);
    expect(hex(e)).toBe('f0f1f2f3f4f5f6f7f8f9fafbfcfdff00');
  });

  it('an IV of sixteen ff bytes with a two-block message matches WebCrypto AES-CTR (128-bit counter)', async () => {
    const key = randomBytes(16);
    const iv = fromHex('ffffffffffffffffffffffffffffffff');
    const msg = randomBytes(32);
    expect(hex(encryptWithIv(key, iv, msg).subarray(16))).toBe(hex(await webcryptoCtr(key, iv, msg)));
  });

  it('an IV whose low 64 bits are all ones carries into the high half (not a 64-bit wrap)', async () => {
    const key = randomBytes(16);
    const iv = fromHex('0000000000000000ffffffffffffffff');
    const msg = randomBytes(32);
    expect(hex(encryptWithIv(key, iv, msg).subarray(16))).toBe(hex(await webcryptoCtr(key, iv, msg)));
  });

  it('agrees with WebCrypto AES-CTR on 32 random keys, IVs and messages of 0..100 bytes', async () => {
    for (let i = 0; i < 32; i++) {
      const key = randomBytes(16);
      const iv = randomBytes(16);
      const msg = randomBytes(Math.floor(Math.random() * 101));
      expect(hex(encryptWithIv(key, iv, msg).subarray(16))).toBe(hex(await webcryptoCtr(key, iv, msg)));
    }
  });

  it('an empty message encrypts to the IV alone and decrypts to an empty message', () => {
    const key = randomBytes(16);
    const ct = encrypt(key, new Uint8Array());
    expect(ct.length).toBe(16);
    expect(decrypt(key, ct)).toEqual(new Uint8Array());
  });

  it('the honest encryptor surfaces its IV as the first 16 bytes and round-trips', () => {
    const key = randomBytes(16);
    const msg = utf8('Attack at dawn.');
    const ct = encrypt(key, msg);
    expect(ct.length).toBe(16 + msg.length);
    expect(ivOf(ct).length).toBe(16);
    expect(hex(decrypt(key, ct)!)).toBe(hex(msg));
  });

  it('two honest encryptions of one message differ in their IV', () => {
    const key = randomBytes(16);
    const msg = utf8('same message');
    expect(hex(ivOf(encrypt(key, msg)))).not.toBe(hex(ivOf(encrypt(key, msg))));
  });

  it('a ciphertext shorter than one IV is refused with null', () => {
    expect(decrypt(randomBytes(16), new Uint8Array(15))).toBeNull();
  });

  it('refuses an IV that is not 16 bytes', () => {
    expect(() => encryptWithIv(randomBytes(16), new Uint8Array(12), new Uint8Array())).toThrow(/IV must be 16 bytes/);
  });

  it('exposes itself as a BaseScheme with 16 bytes of coins that ARE the IV', async () => {
    const key = randomBytes(16);
    const coins = randomBytes(16);
    const ct = await CTR_DOLLAR.encrypt(key, utf8('x'), coins);
    expect(CTR_DOLLAR.coinBytes).toBe(16);
    expect(hex(ivOf(ct))).toBe(hex(coins));
  });
});
