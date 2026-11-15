import { describe, expect, it } from 'vitest';
import { hex, randomBytes } from './bytes.js';
import { decrypt } from './ctr.js';
import { BiasedEncryptor } from './subvert-bias.js';
import { IvReplacementEncryptor } from './subvert-iv.js';

/**
 * Check B: for 1,000 random keys and messages of 0..100 bytes, under BOTH
 * subversions, honest decryption of the subverted ciphertext equals the
 * plaintext. The IV-replacement encryptor is fresh for every key so its
 * leaking first ciphertext is the one exercised; the biased encryptor is one
 * instance whose counter walks the key bits.
 */
describe('Check B: round trips under both subversions', () => {
  it('[slow] 1,000 random keys and messages: IV replacement and biased ciphertexts both decrypt honestly', async () => {
    const biasKey = randomBytes(32);
    const biased = new BiasedEncryptor(biasKey);
    for (let i = 0; i < 1000; i++) {
      const key = randomBytes(16);
      const msg = randomBytes(Math.floor(Math.random() * 101));
      const iv = new IvReplacementEncryptor(randomBytes(16));
      const a = await iv.encrypt(key, msg);
      expect(hex(decrypt(key, a.ct)!)).toBe(hex(msg));
      const b = await biased.encrypt(key, msg);
      expect(b.ok).toBe(true);
      if (b.ok) expect(hex(decrypt(key, b.ct)!)).toBe(hex(msg));
    }
  });
});
