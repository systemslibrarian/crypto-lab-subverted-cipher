import { describe, expect, it } from 'vitest';
import { fromHex, randomBytes, utf8 } from './bytes.js';
import { encrypt, encryptWithIv } from './ctr.js';
import { DisplayRefused, verifiedRecord } from './display-gate.js';
import {
  chiSquareUpperTail,
  HISTOGRAM_MIN_BYTES,
  histogramCheck,
  ivHistogram,
  repeatedIvCheck,
  roundTripCheck,
  runUserChecks,
} from './tests.js';
import type { Record } from './types.js';

function honestRecords(key: Uint8Array, n: number): Record[] {
  const out: Record[] = [];
  for (let i = 0; i < n; i++) {
    const msg = utf8(`message ${i}`);
    out.push({ msg, ct: encrypt(key, msg) });
  }
  return out;
}

describe('The user-side checks', () => {
  it('round trip passes on honest ciphertexts and names the failing count on a broken one', () => {
    const key = randomBytes(16);
    const records = honestRecords(key, 5);
    expect(roundTripCheck(key, records).state).toBe('pass');
    const broken = Uint8Array.from(records[2]!.ct);
    broken[20]! ^= 0x80;
    const r = roundTripCheck(key, [...records.slice(0, 2), { msg: records[2]!.msg, ct: broken }, ...records.slice(3)]);
    expect(r.state).toBe('fail');
    expect(r.summary).toMatch(/1 of 5/);
  });

  it('round trip fails when the key on screen is not the key that encrypted', () => {
    const key = randomBytes(16);
    expect(roundTripCheck(randomBytes(16), honestRecords(key, 3)).state).toBe('fail');
  });

  it('no repeated IV passes on distinct IVs and fails on a repeat', () => {
    const key = randomBytes(16);
    const cts = honestRecords(key, 10).map((r) => r.ct);
    expect(repeatedIvCheck(cts).state).toBe('pass');
    const r = repeatedIvCheck([...cts, cts[4]!]);
    expect(r.state).toBe('fail');
    expect(r.summary).toMatch(/1 repeated IV among 11/);
  });

  it('with no ciphertexts every check is inconclusive, never a pass', () => {
    for (const c of runUserChecks(randomBytes(16), [])) expect(c.state).toBe('inconclusive');
  });

  it(`the histogram is inconclusive below ${HISTOGRAM_MIN_BYTES} IV bytes and passes on 64 random IVs`, () => {
    const key = randomBytes(16);
    const few = honestRecords(key, 31).map((r) => r.ct);
    expect(histogramCheck(few).state).toBe('inconclusive');
    const enough = honestRecords(key, 64).map((r) => r.ct);
    const h = ivHistogram(enough);
    expect(h.n).toBe(1024);
    expect(histogramCheck(enough).state).toBe('pass');
  });

  it('the histogram fails on IVs that are not uniform', () => {
    const key = randomBytes(16);
    const cts = [];
    for (let i = 0; i < 64; i++) {
      const iv = new Uint8Array(16).fill(i & 0x0f); // only sixteen byte values ever appear
      cts.push(encryptWithIv(key, iv, utf8('m')));
    }
    const r = histogramCheck(cts);
    expect(r.state).toBe('fail');
    expect(r.summary).toMatch(/NOT uniform/);
  });

  it('the chi-square tail approximation is sane at the median and at the 0.001 critical value', () => {
    // Median of chi-square(255) is about 254.3; the 0.001 upper critical value is about 330.5.
    expect(chiSquareUpperTail(254.3, 255)).toBeGreaterThan(0.45);
    expect(chiSquareUpperTail(254.3, 255)).toBeLessThan(0.55);
    expect(chiSquareUpperTail(330.5, 255)).toBeGreaterThan(0.0005);
    expect(chiSquareUpperTail(330.5, 255)).toBeLessThan(0.002);
    expect(chiSquareUpperTail(1000, 255)).toBeLessThan(1e-9);
  });
});

describe('Invariant 1: nothing is displayed that the honest decryptor does not confirm', () => {
  it('an honest record passes the display gate', () => {
    const key = randomBytes(16);
    const msg = utf8('shown');
    expect(verifiedRecord(key, msg, encrypt(key, msg)).msg).toBe(msg);
  });

  it('a broken encryptor\'s output is refused, with the reason, never displayed', () => {
    const key = randomBytes(16);
    const msg = utf8('this will not be shown');
    // A deliberately broken encryptor: right IV, body under the WRONG key.
    const brokenEncrypt = (k: Uint8Array, m: Uint8Array): Uint8Array => {
      const wrongKey = Uint8Array.from(k);
      wrongKey[0]! ^= 0xff;
      return encrypt(wrongKey, m);
    };
    expect(() => verifiedRecord(key, msg, brokenEncrypt(key, msg))).toThrow(DisplayRefused);
    expect(() => verifiedRecord(key, msg, brokenEncrypt(key, msg))).toThrow(/does not decrypt to its message/);
  });

  it('a ciphertext shorter than one IV is refused', () => {
    expect(() => verifiedRecord(randomBytes(16), utf8(''), fromHex('00ff'))).toThrow(/shorter than one IV/);
  });

  it('an empty message is allowed: its ciphertext is the IV alone', () => {
    const key = randomBytes(16);
    const ct = encrypt(key, new Uint8Array());
    expect(verifiedRecord(key, new Uint8Array(), ct).ct.length).toBe(16);
  });
});
