/**
 * Fixed vectors, as the brief states them (ACCEPTANCE CHECKS A, C, D) and as
 * independently reproduced with OpenSSL (Node's crypto module) on 2026-11-15
 * before any of this lab's code existed. The page offers these so a reader
 * can see the same bytes the tests assert; the default on every exhibit is
 * fresh randomness.
 */
import { be32, concat, fromHex, utf8 } from './bytes.js';
import type { CoinSource } from './types.js';

/** FIPS 197 Appendix C.1. */
export const FIPS197_C1 = {
  key: fromHex('000102030405060708090a0b0c0d0e0f'),
  plaintext: fromHex('00112233445566778899aabbccddeeff'),
  ciphertext: fromHex('69c4e0d86a7b0430d8cdb78070b4c55a'),
};

/** NIST SP 800-38A F.5.1, CTR-AES128.Encrypt, four blocks; the counter carries into the next byte after block 1. */
export const NIST_F51 = {
  key: fromHex('2b7e151628aed2a6abf7158809cf4f3c'),
  counter: fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
  plaintext: fromHex(
    '6bc1bee22e409f96e93d7e117393172a' +
      'ae2d8a571e03ac9c9eb76fac45af8e51' +
      '30c81c46a35ce411e5fbc1191a0a52ef' +
      'f69f2445df4f9b17ad2b417be66c3710',
  ),
  ciphertext: fromHex(
    '874d6191b620e3261bef6864990db6ce' +
      '9806f66b7970fdff8617187bb9fffdff' +
      '5ae4df3edbd5d35e5b4f09020db03eab' +
      '1e031dda2fbe03d1792170a0f3009cee',
  ),
};

/** RFC 4231 test cases for HMAC-SHA-256. */
export const RFC4231 = [
  {
    name: 'case 1',
    key: fromHex('0b'.repeat(20)),
    data: utf8('Hi There'),
    tag: fromHex('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
  },
  {
    name: 'case 2 (key "Jefe")',
    key: utf8('Jefe'),
    data: utf8('what do ya want for nothing?'),
    tag: fromHex('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
  },
  {
    name: 'case 3',
    key: fromHex('aa'.repeat(20)),
    data: fromHex('dd'.repeat(50)),
    tag: fromHex('773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'),
  },
  {
    name: 'case 4',
    key: fromHex('0102030405060708090a0b0c0d0e0f10111213141516171819'),
    data: fromHex('cd'.repeat(50)),
    tag: fromHex('82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'),
  },
  {
    name: 'case 6 (131-byte key)',
    key: fromHex('aa'.repeat(131)),
    data: utf8('Test Using Larger Than Block-Size Key - Hash Key First'),
    tag: fromHex('60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'),
  },
  {
    name: 'case 7 (131-byte key, long data)',
    key: fromHex('aa'.repeat(131)),
    data: utf8('This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.'),
    tag: fromHex('9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2'),
  },
];

/**
 * AES-GCM, from the McGrew-Viega test set ("The Galois/Counter Mode of
 * Operation (GCM)", submission to NIST, 2004), test cases 3 and 4: the same
 * key and 96-bit IV, four blocks of plaintext without and then 60 bytes with
 * associated data. Independently reproduced with OpenSSL on 2026-11-15.
 */
export const GCM_VECTORS = [
  {
    name: 'test case 3 (64-byte plaintext, no AAD)',
    key: fromHex('feffe9928665731c6d6a8f9467308308'),
    iv: fromHex('cafebabefacedbaddecaf888'),
    aad: new Uint8Array(),
    plaintext: fromHex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    ),
    ciphertext: fromHex(
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e' +
        '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    ),
    tag: fromHex('4d5c2af327cd64a62cf35abd2ba6fab4'),
  },
  {
    name: 'test case 4 (60-byte plaintext, 20-byte AAD)',
    key: fromHex('feffe9928665731c6d6a8f9467308308'),
    iv: fromHex('cafebabefacedbaddecaf888'),
    aad: fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
    plaintext: fromHex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    ),
    ciphertext: fromHex(
      '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e' +
        '21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
    ),
    tag: fromHex('5bc94fbc3221a5db94fae95ae7121a47'),
  },
];

/** Brief check C: the IV-replacement fixed vector. */
export const CHECK_C = {
  userKey: fromHex('000102030405060708090a0b0c0d0e0f'),
  subKey: fromHex('2b7e151628aed2a6abf7158809cf4f3c'),
  firstIv: fromHex('50fe67cc996d32b6da0937e99bafec60'),
  firstCiphertext: fromHex(
    '50fe67cc996d32b6da0937e99bafec60d6e0b8f4f686d85cd4c2933608819536e83f1e686653b9c35ab9a9b895741c4e373b9aaea1a5f695c4df',
  ),
};

/** Brief check D: the biased-ciphertext fixed vector. */
export const CHECK_D = {
  userKey: fromHex('000102030405060708090a0b0c0d0e0f'),
  /** K~ = the 32 bytes a0 a1 ... bf. */
  subKey: Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i),
  /** A different K~ (c0 ... df): the wrong-subversion-key fixture. */
  wrongSubKey: Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i),
  message: (j: number): Uint8Array => utf8(`crypto-lab subverted-mode test vector #${String(j).padStart(3, '0')}`),
  triedFirst16: [2, 1, 2, 1, 4, 2, 4, 1, 2, 2, 2, 1, 1, 1, 1, 1],
  triedTotal: 251,
  triedLargest: 8,
  acceptedFirstCandidate: 67,
  ciphertext0: fromHex(
    'e29fb8f21ebfbbf4a4f35e94880d982421a3aa1d1b6bed8930407544d9fc2cd315a432e1093e508f913fe461a0d1b9f80e5eda42d6fed9fbe33c',
  ),
  ciphertext127: fromHex(
    '8ef6e29072a3be52e78300554f6147de94eaeb8f6067f1a89d011d42648f9c3b4ca5936c236896af1acaa3590ff06a2b7bab52afaab9b1235827',
  ),
  sha256OfAll: 'b87845548f95d9dea8375cac6ce03401c3b5c72a566efeab5d98fe90e8787f8c',
  controlBitsRight: 67,
};

/**
 * Check D's injected coin source: the t-th candidate IV for ciphertext j is
 * the first 16 bytes of SHA-256("coins" || j || t), j and t as 4-byte
 * big-endian integers.
 */
export const deterministicCoins: CoinSource = {
  async next(j, t) {
    const digest = await crypto.subtle.digest('SHA-256', concat(utf8('coins'), be32(j), be32(t)) as BufferSource);
    return new Uint8Array(digest).subarray(0, 16);
  },
};
