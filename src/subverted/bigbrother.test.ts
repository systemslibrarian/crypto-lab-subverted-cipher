import { describe, expect, it } from 'vitest';
import { decryptAll, extractKeyBits, recoverKeyFromIv } from './bigbrother.js';
import { hex, randomBytes, utf8 } from './bytes.js';
import { BiasedEncryptor } from './subvert-bias.js';
import { IvReplacementEncryptor } from './subvert-iv.js';
import { CHECK_D, deterministicCoins } from './vectors.js';

describe('The holder of the subversion key (extraction only)', () => {
  it('invariant 3: both recovery functions take exactly (subversion key, ciphertexts) and nothing else', () => {
    // Function arity: a defaulted parameter does not count, so each signature
    // is two required arguments -- there is no slot a user key could enter by.
    expect(recoverKeyFromIv.length).toBe(2);
    expect(extractKeyBits.length).toBe(2);
    expect(decryptAll.length).toBe(2);
  });

  it('fewer than 128 ciphertexts: the bits known so far, and NO key', async () => {
    const sub = new BiasedEncryptor(CHECK_D.subKey, undefined, deterministicCoins);
    const cts: Uint8Array[] = [];
    for (let j = 0; j < 37; j++) {
      const r = await sub.encrypt(CHECK_D.userKey, CHECK_D.message(j));
      if (r.ok) cts.push(r.ct);
    }
    const x = await extractKeyBits(CHECK_D.subKey, cts);
    expect(x.known).toBe(37);
    expect(x.key).toBeNull();
    expect(x.bits.slice(0, 37).every((b) => b === 0 || b === 1)).toBe(true);
    expect(x.bits.slice(37).every((b) => b === null)).toBe(true);
    expect(x.perCiphertext.length).toBe(37);
  });

  it('no ciphertexts: nothing known, no key', async () => {
    const x = await extractKeyBits(CHECK_D.subKey, []);
    expect(x.known).toBe(0);
    expect(x.key).toBeNull();
  });

  it('the wrong subversion key extracts 128 bits that are NOT the key', async () => {
    const sub = new BiasedEncryptor(CHECK_D.subKey, undefined, deterministicCoins);
    const cts: Uint8Array[] = [];
    for (let j = 0; j < 128; j++) {
      const r = await sub.encrypt(CHECK_D.userKey, CHECK_D.message(j));
      if (r.ok) cts.push(r.ct);
    }
    const x = await extractKeyBits(CHECK_D.wrongSubKey, cts);
    expect(x.known).toBe(128);
    expect(x.key).not.toBeNull();
    expect(hex(x.key!)).not.toBe(hex(CHECK_D.userKey));
  });

  it('section 4.1: a recovered key decrypts everything after the first ciphertext', async () => {
    const subKey = randomBytes(16);
    const userKey = randomBytes(16);
    const sub = new IvReplacementEncryptor(subKey);
    const msgs = [utf8('first'), utf8('second'), utf8(''), utf8('fourth, longer than one block of sixteen bytes')];
    const cts: Uint8Array[] = [];
    for (const m of msgs) cts.push((await sub.encrypt(userKey, m)).ct);
    const recovered = recoverKeyFromIv(subKey, cts[0]!)!;
    expect(hex(recovered)).toBe(hex(userKey));
    const pts = decryptAll(recovered, cts);
    pts.forEach((pt, i) => expect(hex(pt!)).toBe(hex(msgs[i]!)));
  });

  it('section 4.1: a ciphertext shorter than an IV yields no key', () => {
    expect(recoverKeyFromIv(randomBytes(16), new Uint8Array(3))).toBeNull();
  });
});
