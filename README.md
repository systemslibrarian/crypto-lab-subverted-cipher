# Subverted Cipher

Algorithm-substitution attacks on AES counter mode, in the browser: an encryptor that
decrypts correctly and passes every test a user can run while handing its key to whoever
holds the subversion key, by IV replacement in one ciphertext and by biased ciphertexts at
one key bit each, then a deterministic unique-ciphertext scheme with no room to hide a bit.

**Live demo:** <https://systemslibrarian.github.io/crypto-lab-subverted-cipher/>

---

## What It Is

An interactive build of the two algorithm-substitution attacks (ASAs) in Mihir Bellare,
Kenneth G. Paterson and Phillip Rogaway, *Security of Symmetric Encryption against Mass
Surveillance* (CRYPTO 2014; IACR ePrint [2014/438](https://eprint.iacr.org/2014/438)), and
of the defence the same paper proves works.

**The setting.** The user's encryption code has been replaced. The replacement has to
produce ciphertexts the honest decryptor decrypts correctly, and it has to be
indistinguishable from the real code even to a tester who knows the user's key. Whoever
holds a separate subversion key `K~` gains the user's key `K`.

**The base scheme** is CTR$: `ciphertext = IV ‖ AES-CTR_K(message)`, with a fresh random
16-byte IV used as the initial counter block and the counter incremented as a 128-bit
big-endian integer. It is randomized, stateless, and it surfaces its IV — which is exactly
the class of scheme the paper shows is subvertible.

**The two attacks.**

- **IV replacement** (paper §4.1). On the first encryption only, the subverted code sets
  `IV ← E(K~, K)`: one block-cipher call on the user's key under the subversion key. The
  holder computes `K = E⁻¹(K~, IV)` from that one ciphertext and reads everything sent
  afterwards. It happens once because `E(K~, K)` is deterministic and a repeated IV would be
  visible — which is why the attack carries state.
- **Biased ciphertexts** (paper §4.2). The subverted code keeps a counter `j` and, for the
  `j`-th message, draws fresh coins until the ciphertext they produce satisfies
  `F(K~, C ‖ j) = K[j]`, where `F` is a one-bit PRF. The holder evaluates `F` on each
  ciphertext and reads the key off, one bit per ciphertext, 128 ciphertexts for an AES-128
  key, whatever the messages were. The paper calls this universal: it needs only that the
  scheme is randomized, stateless and coin-injective, with about seven bits of randomness.

**The defence** (paper §5). A scheme has **unique ciphertexts** if, for each key, message,
associated data and decryptor state, at most one ciphertext decrypts to that message.
Theorem 4 says a subversion of such a scheme that keeps decryption correct has surveillance
advantage **zero** — the subverted code is forced to emit the same ciphertext the honest
code would have. Exhibit 6 builds one.

**What is real.** AES-128 is written out here (FIPS 197) because the attacks need single
blocks enciphered and deciphered in the open, and it is cross-checked against WebCrypto on
random blocks in both directions; HMAC-SHA-256 and AES-GCM are WebCrypto's. Every rate on
the page is counted from runs with the real primitives. No key or subversion key leaves the
browser or outlives the session.

**Not production crypto — a teaching demo.** Nothing here should be used to protect
anything.

---

## Exhibits

1. **The honest encryptor.** CTR$ with real AES: encrypt, decrypt, see the IV as the first
   16 bytes, and run the three checks a careful user can run — round trip, no repeated IV,
   and a chi-square test on the IV byte histogram. Five published vectors (FIPS 197,
   NIST SP 800-38A, RFC 4231, McGrew–Viega GCM) are recomputed in your browser and compared
   with the documents.
2. **Swap the code.** A switch replaces the encryptor. The ciphertexts change; the checks do
   not. A second, clearly separated panel is the holder of the subversion key, showing the
   one thing the user cannot compute: `F(K~, C, j)`, which agrees with the key bit about half
   the time under the honest encryptor and every time under the subverted one.
3. **IV replacement.** One ciphertext carries the key. The right panel deciphers its IV and
   then reads every message, including the ones sent afterwards. Give the right panel a
   different `K~` and the recovery correctly fails.
4. **Biased ciphertexts.** Encrypt your own messages or press *Encrypt 128*. The right panel
   fills the key in one bit per ciphertext, with the number of candidates the subverter tried
   shown per ciphertext. A step-by-step view draws candidates one at a time, so you can watch
   a ciphertext being discarded for saying the wrong bit. The control: the same extraction on
   honest ciphertexts, which gets about half the bits right by chance and recovers nothing.
5. **How little randomness it needs.** Measured failure rate of the subverter against
   `2^−(2^c)` for coin budgets of 1 to 4 bits, counted from runs with the run count shown.
6. **A scheme with nothing to choose.** AES-128-GCM with the nonce taken from a counter both
   sides keep — the paper's §5 construction from nonce-based schemes (Theorem 6). Encrypting
   twice gives byte-identical ciphertexts; every single-bit change to a ciphertext is
   rejected; a receiver whose counter is out of step rejects; and the biased-ciphertext
   subverter, handed this scheme, reports that it has no coins to choose and emits exactly
   the honest ciphertext.

**Not in scope**, and said so on the page: public-key (asymmetric) subversion keys (the
paper's appendix B); the stateless variant from the later work of Bellare, Jaeger and Kane;
subversion of signatures or of key generation; any claim that the statistical checks in
exhibits 1 and 2 *prove* undetectability — they illustrate it, and the proof is the paper's
and rests on `F` being a PRF; and any claim about a real product.

---

## When to Use It

- To understand why "the IV must be chosen at random" is not a checkable requirement, and
  what follows from that.
- To see why standards work has moved toward deterministic and nonce-based constructions,
  and what that buys.
- To teach the difference between *deterministic* and *unique ciphertexts* — the first does
  not imply the second, and only the second defeats an ASA.

**Do NOT** treat the statistical checks on this page as a detector for subverted software.
They are there to fail to detect: they pass on both attacks, which is the lesson. Detecting
an ASA means reading the code or constraining the scheme, not testing the output.

---

## What Can Go Wrong

The paper's lesson is the danger of choice. Any unverifiable choice an encryptor makes is a
channel:

- **A random IV** is 128 bits of choice, which is 128 bits the encryptor may select for any
  reason it likes.
- **Variable-length padding** is a channel too, and a smaller one is enough: with `c` bits
  of choice the subverter fails to place a key bit only with probability `2^−(2^c)`, which is
  about 1 in 65,000 at four bits. The paper notes SSL 3.0 and TLS 1.0 padding and SSH's
  random padding as exactly this.
- **A nonce an implementation may choose freely** reopens IV replacement even in an AEAD;
  the paper notes that TLS 1.2 and IPsec specify AES-GCM nonces that an implementation may
  pick as it likes.
- **A subverted encryptor that resets** re-leaks, and that is the one way the stateful
  attack becomes visible: a repeated IV.

---

## Real-World Usage

Only what can be cited:

- The paper's own appendix A works through SSL/TLS, IPsec and SSH and finds each vulnerable
  to one of the two attacks, usually through padding or an implementation-chosen nonce.
- **RFC 6979** specifies deterministic ECDSA/DSA nonces, removing a per-signature random
  choice. Its stated motivation is the danger of poor randomness, not surveillance; it is
  cited here as a standard that removed unverifiable choice, which is the property this lab
  is about.
- **RFC 8452** (AES-GCM-SIV) and the nonce-misuse-resistant line of work remove the harm of
  a repeated nonce. That is a different goal from surveillance resistance, and neither
  document claims the latter.
- **OCB** (RFC 7253) is named in the paper as a non-degenerate nonce-based scheme, which is
  the property Theorem 6 needs.

No claim is made that any deployed system was subverted this way.

---

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-subverted-cipher/
npm test           # the unit suite
npm run build      # maintenance controls, typecheck, production build
npm run test:a11y  # builds, serves, then the axe WCAG gate and the claims suite
```

---

## Related Demos

- [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) — the
  Dual_EC_DRBG backdoor: a subverted *generator* rather than a subverted *encryptor*.
- [Subliminal Channels](https://systemslibrarian.github.io/crypto-lab-subliminal-channels/)
  — the same idea in a signature nonce: choosing among valid outputs to carry a bit.
- [Anamorphic Channel](https://systemslibrarian.github.io/crypto-lab-anamorphic/) — the
  cooperative mirror image, where the sender *wants* the hidden channel.

---

## Build & Verify

**124 tests pass** — 85 unit tests (Vitest, in `src/**/*.test.ts`), 21 browser claims tests,
a 2-test WCAG gate, and 16 maintenance controls the build runs before it compiles anything.

Known-answer tests, each checked against its document:

| Vector | File |
|---|---|
| AES-128, FIPS 197 Appendix C.1, both directions | `src/subverted/block.test.ts` |
| AES-128-CTR, NIST SP 800-38A F.5.1 (the counter carries) | `src/subverted/ctr.test.ts` |
| HMAC-SHA-256, RFC 4231 cases 1, 2, 3, 4, 6, 7 | `src/subverted/prf.test.ts` |
| AES-128-GCM, McGrew–Viega test cases 3 and 4 | `src/subverted/unique.test.ts` |

The hand-written AES is additionally cross-checked against WebCrypto on 64 random blocks in
each direction, and counter mode against WebCrypto's AES-CTR on 32 random inputs plus two
carry cases an ordinary IV never reaches.

**The fixed subversion vector.** With `K = 000102030405060708090a0b0c0d0e0f`, `K~` the 32
bytes `a0 a1 … bf`, messages `crypto-lab subverted-mode test vector #000` … `#127` and a
deterministic coin source, the 128 subverted ciphertexts have

```
SHA-256 = b87845548f95d9dea8375cac6ce03401c3b5c72a566efeab5d98fe90e8787f8c
```

with 251 candidates tried in total, the longest run 8, and 67 ciphertexts accepting their
first candidate. Extraction returns `K` exactly; the same extraction over honest ciphertexts
gets 67 of 128 bits right, which is chance. That vector is what pins this lab's concrete
choices — the bit order, the encoding of `j`, and which bit of the HMAC `F` reads.

**Uniqueness argument for exhibit 6**, in our own words: fix the key and the nonce. The
counter-mode keystream is then fixed, so the only ciphertext body that decrypts to a given
message is that message XOR the keystream — one string, not a choice. The tag is a
deterministic function of the key, nonce, associated data and that body (GHASH over them,
then one more block-cipher call), so exactly one tag is accepted with it. One body and one
tag means the acceptance set has one element, which is the unique-ciphertext condition; the
counter nonce supplies the state Theorem 6 needs. The page demonstrates the browser-sized
consequence — every single-bit neighbour of a real ciphertext is rejected — which is a
demonstration, not the proof.

**The accessibility gate** scans the production build with `@axe-core/playwright` for zero
WCAG 2.1 A/AA violations across every driven state at 1280px and 380px, and the GitHub Pages
deploy is blocked if it fails. It asserts axe's `incomplete` bucket as well as its
`violations`, computes contrast arithmetically over composited colours, measures non-text
contrast against a ratchet baseline that is currently empty, and checks reflow, which axe
has no rule for.

**Mutation testing** (`npm run test:mutation`) applies each patch in
`e2e/verdict-mutations.json` to an isolated `git archive HEAD` tree, confirms the build
succeeds and the bundle hash moves, and confirms the owning test fails. Eight mutations are
recorded, including key bits taken least-significant-first, `j` encoded as one byte, `F`
reading the wrong bit, the subverter skipping its test of `F`, the counter never advancing,
IV replacement applied to every ciphertext, "key recovered" rendered without comparing to
the key, and the counter-mode increment wrapping at 64 bits.

---

## Performance

Measured in Chromium on an Apple-silicon laptop. The 128-ciphertext run in exhibit 4 does
about 276 AES-CTR encryptions and as many HMAC evaluations in **0.14 s**. Exhibit 5 at its
default 2,000 runs per budget does 8,000 subverted encryptions across four budgets in
**0.3 s**, with a progress line between budgets. Exhibit 6 tests every single-bit change to
a 58-byte ciphertext — 464 real AES-GCM decryptions — in **0.01 s**. The slow part of this
lab is not the cryptography: it is the 1,000-key round-trip test and the 150,000-encryption
statistics suite, which together account for most of the unit suite's 44 seconds.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
