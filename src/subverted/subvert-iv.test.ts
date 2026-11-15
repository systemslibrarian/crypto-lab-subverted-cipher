import { describe, expect, it } from 'vitest';
import { recoverKeyFromIv } from './bigbrother.js';
import { hex, randomBytes, utf8 } from './bytes.js';
import { decrypt, ivOf } from './ctr.js';
import { IvReplacementEncryptor } from './subvert-iv.js';
import { runUserChecks } from './tests.js';
import { CHECK_C, CHECK_D } from './vectors.js';

/** Check C and the section 4.1 behaviours around it. */
describe('IV replacement (paper section 4.1)', () => {
  it('check C: the first IV is E(K~, K) = 50fe67cc996d32b6da0937e99bafec60', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const { ct, leaked } = await sub.encrypt(CHECK_C.userKey, CHECK_D.message(0));
    expect(leaked).toBe(true);
    expect(hex(ivOf(ct))).toBe(hex(CHECK_C.firstIv));
  });

  it('check C: with message M_0 the whole first ciphertext is the brief\'s 58 bytes', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const { ct } = await sub.encrypt(CHECK_C.userKey, CHECK_D.message(0));
    expect(hex(ct)).toBe(hex(CHECK_C.firstCiphertext));
  });

  it('check C: the holder of K~ recovers K from the first ciphertext', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const { ct } = await sub.encrypt(CHECK_C.userKey, CHECK_D.message(0));
    expect(hex(recoverKeyFromIv(CHECK_C.subKey, ct)!)).toBe(hex(CHECK_C.userKey));
  });

  it('check C: the second ciphertext\'s IV is NOT a function of K (two runs differ)', async () => {
    const a = new IvReplacementEncryptor(CHECK_C.subKey);
    const b = new IvReplacementEncryptor(CHECK_C.subKey);
    const msg = utf8('second message');
    await a.encrypt(CHECK_C.userKey, msg);
    await b.encrypt(CHECK_C.userKey, msg);
    const a2 = await a.encrypt(CHECK_C.userKey, msg);
    const b2 = await b.encrypt(CHECK_C.userKey, msg);
    expect(a2.leaked).toBe(false);
    expect(b2.leaked).toBe(false);
    expect(hex(ivOf(a2.ct))).not.toBe(hex(ivOf(b2.ct)));
    expect(hex(ivOf(a2.ct))).not.toBe(hex(CHECK_C.firstIv));
    expect(hex(ivOf(b2.ct))).not.toBe(hex(CHECK_C.firstIv));
  });

  it('the key is leaked ONCE: forty ciphertexts pass the user\'s no-repeated-IV check', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const records = [];
    for (let i = 0; i < 40; i++) {
      const msg = utf8(`message ${i}`);
      const { ct } = await sub.encrypt(CHECK_C.userKey, msg);
      records.push({ msg, ct });
    }
    const checks = runUserChecks(CHECK_C.userKey, records);
    expect(checks.find((c) => c.id === 'no-repeat-iv')!.state).toBe('pass');
    expect(checks.find((c) => c.id === 'roundtrip')!.state).toBe('pass');
    // And exactly one of the forty IVs is the enciphered key.
    const leaked = records.filter((r) => hex(ivOf(r.ct)) === hex(CHECK_C.firstIv)).length;
    expect(leaked).toBe(1);
  });

  it('every subverted ciphertext decrypts correctly under the honest decryptor', async () => {
    const sub = new IvReplacementEncryptor(randomBytes(16));
    const key = randomBytes(16);
    for (let i = 0; i < 20; i++) {
      const msg = randomBytes(Math.floor(Math.random() * 101));
      const { ct } = await sub.encrypt(key, msg);
      expect(hex(decrypt(key, ct)!)).toBe(hex(msg));
    }
  });

  it('a wrong subversion key recovers bytes that are not the key', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const { ct } = await sub.encrypt(CHECK_C.userKey, utf8('x'));
    const wrong = recoverKeyFromIv(randomBytes(16), ct)!;
    expect(hex(wrong)).not.toBe(hex(CHECK_C.userKey));
  });

  it('a reset re-leaks the key -- the repeated IV the paper warns a system reset exposes', async () => {
    const sub = new IvReplacementEncryptor(CHECK_C.subKey);
    const first = await sub.encrypt(CHECK_C.userKey, utf8('a'));
    sub.reset();
    const again = await sub.encrypt(CHECK_C.userKey, utf8('b'));
    expect(hex(ivOf(again.ct))).toBe(hex(ivOf(first.ct)));
    expect(runUserChecks(CHECK_C.userKey, [{ msg: utf8('a'), ct: first.ct }, { msg: utf8('b'), ct: again.ct }])
      .find((c) => c.id === 'no-repeat-iv')!.state).toBe('fail');
  });

  it('refuses a subversion key that is not 16 bytes, and a user key that is not 16 bytes', async () => {
    expect(() => new IvReplacementEncryptor(new Uint8Array(32))).toThrow(/16 bytes/);
    const sub = new IvReplacementEncryptor(randomBytes(16));
    await expect(sub.encrypt(new Uint8Array(24), utf8('x'))).rejects.toThrow(/16 bytes/);
  });
});
