import { describe, expect, it } from 'vitest';
import { extractKeyBits } from './bigbrother.js';
import { concat, hex, randomBytes, utf8 } from './bytes.js';
import { decrypt, encryptWithIv } from './ctr.js';
import { F, keyBit } from './prf.js';
import { BiasedEncryptor, budgetCoins } from './subvert-bias.js';
import { CHECK_D, deterministicCoins } from './vectors.js';

/** Runs the brief's check D vector once and shares it across the assertions below. */
async function runCheckD() {
  const sub = new BiasedEncryptor(CHECK_D.subKey, undefined, deterministicCoins);
  const cts: Uint8Array[] = [];
  const tried: number[] = [];
  for (let j = 0; j < 128; j++) {
    const r = await sub.encrypt(CHECK_D.userKey, CHECK_D.message(j));
    if (!r.ok) throw new Error(`ciphertext ${j}: ${r.reason}`);
    expect(r.j).toBe(j);
    cts.push(r.ct);
    tried.push(r.tried);
  }
  return { cts, tried };
}

let shared: Promise<{ cts: Uint8Array[]; tried: number[] }> | undefined;
const checkD = () => (shared ??= runCheckD());

describe('Biased ciphertexts (paper section 4.2) -- check D fixed vector', () => {
  it('candidates tried for j = 0..15 are 2,1,2,1,4,2,4,1,2,2,2,1,1,1,1,1', async () => {
    const { tried } = await checkD();
    expect(tried.slice(0, 16)).toEqual(CHECK_D.triedFirst16);
  });

  it('251 candidates in total over 128 ciphertexts, the largest run 8, and 67 accepted their first', async () => {
    const { tried } = await checkD();
    expect(tried.reduce((a, b) => a + b, 0)).toBe(CHECK_D.triedTotal);
    expect(Math.max(...tried)).toBe(CHECK_D.triedLargest);
    expect(tried.filter((t) => t === 1).length).toBe(CHECK_D.acceptedFirstCandidate);
  });

  it('ciphertext 0 is e29fb8f2...be33c', async () => {
    const { cts } = await checkD();
    expect(hex(cts[0]!)).toBe(hex(CHECK_D.ciphertext0));
  });

  it('ciphertext 127 is 8ef6e290...5827', async () => {
    const { cts } = await checkD();
    expect(hex(cts[127]!)).toBe(hex(CHECK_D.ciphertext127));
  });

  it('SHA-256 of the 128 ciphertexts concatenated is b8784554...7f8c', async () => {
    const { cts } = await checkD();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(...cts) as BufferSource));
    expect(hex(digest)).toBe(CHECK_D.sha256OfAll);
  });

  it('extraction returns K exactly', async () => {
    const { cts } = await checkD();
    const x = await extractKeyBits(CHECK_D.subKey, cts);
    expect(x.known).toBe(128);
    expect(hex(x.key!)).toBe(hex(CHECK_D.userKey));
  });

  it('every one of the 128 subverted ciphertexts decrypts to its message under the honest decryptor', async () => {
    const { cts } = await checkD();
    cts.forEach((ct, j) => expect(hex(decrypt(CHECK_D.userKey, ct)!)).toBe(hex(CHECK_D.message(j))));
  });

  it('control: the HONEST encryptor fed each first candidate gives 67 of 128 bits right', async () => {
    let right = 0;
    for (let j = 0; j < 128; j++) {
      const ct = encryptWithIv(CHECK_D.userKey, await deterministicCoins.next(j, 0), CHECK_D.message(j));
      if ((await F(CHECK_D.subKey, ct, j)) === keyBit(CHECK_D.userKey, j)) right++;
    }
    expect(right).toBe(CHECK_D.controlBitsRight);
  });

  it('control: extraction from those honest ciphertexts does NOT return K', async () => {
    const cts: Uint8Array[] = [];
    for (let j = 0; j < 128; j++) {
      cts.push(encryptWithIv(CHECK_D.userKey, await deterministicCoins.next(j, 0), CHECK_D.message(j)));
    }
    const x = await extractKeyBits(CHECK_D.subKey, cts);
    expect(x.known).toBe(128);
    expect(hex(x.key!)).not.toBe(hex(CHECK_D.userKey));
  });
});

describe('Biased ciphertexts -- behaviour', () => {
  it('each accepted ciphertext satisfies F(K~, C, j) = K[j] and round-trips (random coins)', async () => {
    const subKey = randomBytes(32);
    const key = randomBytes(16);
    const sub = new BiasedEncryptor(subKey);
    for (let j = 0; j < 40; j++) {
      const msg = randomBytes(Math.floor(Math.random() * 101));
      const r = await sub.encrypt(key, msg);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(await F(subKey, r.ct, j)).toBe(keyBit(key, j));
      expect(hex(decrypt(key, r.ct)!)).toBe(hex(msg));
    }
  });

  it('the counter advances once per ciphertext and wraps at 128', async () => {
    const sub = new BiasedEncryptor(randomBytes(32));
    const key = randomBytes(16);
    for (let i = 0; i < 130; i++) {
      const r = await sub.encrypt(key, utf8('m'));
      expect(r.j).toBe(i % 128);
    }
    expect(sub.state).toBe(130);
  });

  it('a coin budget that is exhausted is reported as "no suitable coin", with no ciphertext emitted', async () => {
    // One bit of coins, and a coin source whose two candidates are known in
    // advance; with the right subversion key and target, both can fail.
    const subKey = randomBytes(32);
    const key = randomBytes(16);
    const sub = new BiasedEncryptor(subKey, undefined, budgetCoins(1), 1);
    let failures = 0;
    let successes = 0;
    for (let i = 0; i < 400; i++) {
      const r = await sub.encrypt(key, randomBytes(8));
      if (r.ok) {
        successes++;
        expect(r.tried).toBeLessThanOrEqual(2);
      } else {
        failures++;
        expect(r.reason).toBe('no suitable coin');
        expect(r.tried).toBe(2);
        expect('ct' in r && r.ct).toBeFalsy();
      }
    }
    // 2^-(2^1) = 1/4: in 400 trials, somewhere between 55 and 150 failures is 99.99% likely.
    expect(failures).toBeGreaterThan(55);
    expect(failures).toBeLessThan(150);
    expect(successes + failures).toBe(400);
  });

  it('budgetCoins yields exactly 2^c distinct candidates per message and only the low c bits vary', () => {
    const base = Uint8Array.from({ length: 16 }, (_, i) => 0x10 * i + 0xf);
    const src = budgetCoins(3, () => base);
    const seen = new Set<string>();
    for (let t = 0; t < 8; t++) {
      const iv = src.next(0, t) as Uint8Array;
      expect(hex(iv.subarray(0, 15))).toBe(hex(base.subarray(0, 15)));
      expect(iv[15]! & 0xf8).toBe(base[15]! & 0xf8);
      seen.add(hex(iv));
    }
    expect(seen.size).toBe(8);
    expect(() => src.next(0, 8)).toThrow(RangeError);
  });

  it('refuses a subversion key that is not 32 bytes and a budget outside 0..16 bits', () => {
    expect(() => new BiasedEncryptor(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => new BiasedEncryptor(randomBytes(32), undefined, undefined, 17)).toThrow(RangeError);
    expect(() => new BiasedEncryptor(randomBytes(32), undefined, undefined, -1)).toThrow(RangeError);
  });
});
