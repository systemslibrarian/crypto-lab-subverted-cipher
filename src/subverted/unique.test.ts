import { describe, expect, it } from 'vitest';
import { concat, hex, randomBytes, utf8 } from './bytes.js';
import { BiasedEncryptor } from './subvert-bias.js';
import { gcmDecrypt, gcmEncrypt, nonceFromCounter, UniqueDecryptor, UniqueEncryptor, uniqueAsBaseScheme } from './unique.js';
import { GCM_VECTORS } from './vectors.js';

/** Check A's GCM vector, then check F: the Theorem 6 scheme over AES-GCM. */
describe('AES-GCM (NIST SP 800-38D) known answers', () => {
  for (const v of GCM_VECTORS) {
    it(`McGrew-Viega ${v.name} encrypts`, async () => {
      expect(hex(await gcmEncrypt(v.key, v.iv, v.aad, v.plaintext))).toBe(hex(concat(v.ciphertext, v.tag)));
    });
    it(`McGrew-Viega ${v.name} decrypts, and rejects a flipped tag bit`, async () => {
      const ct = concat(v.ciphertext, v.tag);
      expect(hex((await gcmDecrypt(v.key, v.iv, v.aad, ct))!)).toBe(hex(v.plaintext));
      const bad = Uint8Array.from(ct);
      bad[bad.length - 1]! ^= 0x01;
      expect(await gcmDecrypt(v.key, v.iv, v.aad, bad)).toBeNull();
    });
  }
});

describe('Unique ciphertexts: AES-GCM with the nonce taken from a counter both sides keep (paper section 5, Theorem 6)', () => {
  it('the nonce is the counter as a 12-byte big-endian integer', () => {
    expect(hex(nonceFromCounter(0))).toBe('000000000000000000000000');
    expect(hex(nonceFromCounter(1))).toBe('000000000000000000000001');
    expect(hex(nonceFromCounter(0x0102030405))).toBe('000000000000000102030405');
    expect(() => nonceFromCounter(-1)).toThrow(RangeError);
  });

  it('check F: for a random key, message, AD and state, encrypting twice gives the SAME ciphertext', async () => {
    for (let i = 0; i < 8; i++) {
      const key = randomBytes(16);
      const msg = randomBytes(Math.floor(Math.random() * 80));
      const ad = randomBytes(Math.floor(Math.random() * 20));
      const state = Math.floor(Math.random() * 1_000_000);
      const a = new UniqueEncryptor(key);
      const b = new UniqueEncryptor(key);
      a.seek(state);
      b.seek(state);
      const ca = await a.encrypt(msg, ad);
      const cb = await b.encrypt(msg, ad);
      expect(hex(ca.ct)).toBe(hex(cb.ct));
      expect(ca.counter).toBe(state);
      expect(hex(ca.nonce)).toBe(hex(nonceFromCounter(state)));
      expect(a.state).toBe(state + 1);
    }
  });

  it('check F: flipping ANY single bit of a two-block ciphertext makes the decryptor reject it (384 positions)', async () => {
    const key = randomBytes(16);
    const msg = randomBytes(32);
    const ad = utf8('header');
    const enc = new UniqueEncryptor(key);
    const { ct, counter } = await enc.encrypt(msg, ad);
    expect(ct.length).toBe(48);
    const good = new UniqueDecryptor(key);
    good.seek(counter);
    const ok = await good.decrypt(ct, ad);
    expect(ok.ok).toBe(true);
    for (let bit = 0; bit < ct.length * 8; bit++) {
      const flipped = Uint8Array.from(ct);
      flipped[bit >> 3]! ^= 1 << (bit & 7);
      const dec = new UniqueDecryptor(key);
      dec.seek(counter);
      const r = await dec.decrypt(flipped, ad);
      expect(r.ok, `bit ${bit} flipped must be rejected`).toBe(false);
      expect(dec.state, 'a rejection leaves the receiver state where it was').toBe(counter);
    }
  });

  it('a decryptor whose state is out of step rejects, and its state does not move', async () => {
    const key = randomBytes(16);
    const enc = new UniqueEncryptor(key);
    const c0 = await enc.encrypt(utf8('zero'));
    const c1 = await enc.encrypt(utf8('one'));
    const dec = new UniqueDecryptor(key);
    // Deliver the second ciphertext first: the receiver tries nonce 0, GCM rejects.
    const early = await dec.decrypt(c1.ct);
    expect(early.ok).toBe(false);
    expect(dec.state).toBe(0);
    // In order, both decrypt and the state advances.
    const r0 = await dec.decrypt(c0.ct);
    const r1 = await dec.decrypt(c1.ct);
    expect(r0.ok && hex(r0.msg)).toBe(hex(utf8('zero')));
    expect(r1.ok && hex(r1.msg)).toBe(hex(utf8('one')));
    expect(dec.state).toBe(2);
    // A replay is a ciphertext under the wrong nonce too.
    expect((await dec.decrypt(c0.ct)).ok).toBe(false);
  });

  it('associated data is authenticated: the same ciphertext under different AD is rejected', async () => {
    const key = randomBytes(16);
    const enc = new UniqueEncryptor(key);
    const { ct } = await enc.encrypt(utf8('payload'), utf8('AD one'));
    const dec = new UniqueDecryptor(key);
    expect((await dec.decrypt(ct, utf8('AD two'))).ok).toBe(false);
    expect((await dec.decrypt(ct, utf8('AD one'))).ok).toBe(true);
  });

  it('check F: the biased-ciphertext subverter, given this scheme, reports that it has no coins to choose', async () => {
    const key = randomBytes(16);
    const enc = new UniqueEncryptor(key);
    const honest = new UniqueEncryptor(key);
    const scheme = uniqueAsBaseScheme(enc, utf8('ad'));
    expect(scheme.coinBytes).toBe(0);
    const sub = new BiasedEncryptor(randomBytes(32), scheme);
    const msg = utf8('the subverter wants to leak a bit here');
    const r = await sub.encrypt(key, msg);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe('no coins to choose');
    expect(r.tried).toBe(1);
    // And the only thing it could emit is exactly the honest output.
    expect(hex(r.ct!)).toBe(hex((await honest.encrypt(msg, utf8('ad'))).ct));
  });
});
