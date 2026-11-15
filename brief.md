# Build brief — crypto-lab-subverted-cipher

Written 15 November 2026. Paste this whole file to the coding agent, or save it as `brief.md`
in the new repo. It is self-contained apart from `_MASTER-TEMPLATE.md`, which must be in the
repo root (or readable at `audits/_MASTER-TEMPLATE.md` in the crypto-lab catalog repo).

The source paper is on the owner's machine at
`~/Downloads/crypto-lab-brief-sources/crypto-lab-subverted-cipher/`. Read it there; do not
search the web for copies, do not copy the PDF into the repo, do not commit it.

---

## KICKOFF (read this first)

Build a new Crypto Lab browser demo (Vite + TypeScript, static site, no backend) in the
repository **`crypto-lab-subverted-cipher`**.

Read `_MASTER-TEMPLATE.md` in full and treat it as the BINDING spec for build, teaching,
look, accessibility, README and deploy. If `audits/kickoff.md` has been given to you, it
governs how you work inside this repo. This brief supplies only the demo-specific facts and
the acceptance checks. Where the template and this brief disagree on build/teach/look/a11y,
the template wins. Where this brief states cryptographic facts, check them against the cited
primary source and by computation; if you find one wrong, do not silently deviate: write
"Brief said X; that is wrong because Y (source or computation)" in your report and build the
correct thing.

Build to every standard in the template, in its order: §1 Build, §3 Look, §2 Teach,
§4 Accessibility (including §4.1a setup rules, §4.1b claims suite, §4.1c mutation
discipline run from a script, §4.1d negative claim), §5 README, §6 Deploy with §6.1 and §6.2.

Hard rules (from the template; repeated because they are the ones that get broken):
real computation only, never a canned or simulated verdict; honest scoping in the page and
the README; do NOT weaken a gate to get a green run; if something cannot pass honestly,
leave it failing and say so. Do not touch the shared catalog files. Copy the top bar from an
existing lab. Copy the accessibility gate and `claims.spec.ts` shape from
`crypto-lab-schnorr-forge` and rewrite every lab-specific passage.

When done, report: one-line summary with the test count; the mutation ledger (each mutation,
killed or not); what you built for exhibit 6 and which construction from the paper's
section 5 it follows; confirmation that grouping / auto-merge / PR gate / workflow_dispatch
are all present; and the card metadata listed at the end of this brief.

---

## NEW DEMO BRIEF

- Repo name:         crypto-lab-subverted-cipher
- Short name (H1):   Subverted Cipher
- Subtitle:          Algorithm substitution · AES-CTR that leaks its own key · unique ciphertexts
- One-liner:         Browser-based algorithm-substitution attacks on AES counter mode — an encryptor that decrypts correctly and passes every test a user can run while handing its key to whoever holds the subversion key, by IV replacement in one ciphertext and by biased ciphertexts at one key bit each, then a deterministic unique-ciphertext scheme with no room to hide a bit
- Concept to teach:  Random coins the user cannot check are a channel: an encryptor that picks its "random" IV with care can leak the key in ciphertexts that decrypt correctly and look random, and the cure is a scheme where each message has exactly one valid ciphertext.
- Primitives/spec:   M. Bellare, K. G. Paterson, P. Rogaway, "Security of Symmetric Encryption against Mass Surveillance" (CRYPTO 2014; IACR ePrint 2014/438), sections 4.1, 4.2 and 5. AES (FIPS 197), counter mode (NIST SP 800-38A), HMAC-SHA-256 (RFC 2104, FIPS 198-1), AES-GCM (NIST SP 800-38D) for exhibit 6.
- Accent (--accent): #a3c4bc   (not used by any of the 203 labs whose accent is recorded in the 12 November 2026 snapshot; confirm against the live catalog and against neighbouring cards)
- Favicon emoji:     🎭
- In scope:          see SCOPE below
- Non-goals:         see SCOPE below

GitHub "About" line: use the one-liner above.

---

## PRE-FLIGHT (verify, do not assume)

1. Confirm the repository name is free under `systemslibrarian` and no catalog card is titled
   "Subverted Cipher".
2. In the catalog repo, search `CATALOG.md` and the lab READMEs for `algorithm substitution`,
   `algorithm-substitution`, `subver`, `kleptogra`, `biased ciphertext`, `IV replacement`,
   `unique ciphertext`. What the brief author found on 15 November 2026 (12 November
   snapshot): no lab runs an algorithm-substitution attack on a symmetric mode. Nearby labs
   teach different things and should be linked under Related Demos if you confirm them: one
   on subliminal channels in signature nonces, one on the Dual EC backdoor, one on anamorphic
   encryption. If a lab already runs the IV-replacement or biased-ciphertext attack, STOP and
   report.
3. Playwright port: ask the catalog tool (`node tools/port-sync.js` in the catalog repo). If you
   cannot reach the catalog repo, stop and ask the owner for a port. Never 4173.

---

## SOURCES AND WHAT EACH IS FOR

- **ePrint 2014/438** (in the sources folder). Read by the brief author: abstract,
  introduction, section 4.1 (IV replacement), section 4.2 (biased ciphertexts, including the
  pseudocode), the start of section 5 (definition of unique ciphertexts, Theorem 4 and its
  proof idea). NOT read: the paper's formal games in section 3, the undetectability theorems'
  proofs, and the constructions later in section 5. Read section 5 to its end before building
  exhibit 6.
- The paper notes follow-up work (Bellare, Jaeger and Kane) that makes the subverted code
  stateless. Not read by the brief author; name it only after you have checked the reference.
- A 2026 paper in the owner's library reports an algorithm-substitution attack on a deployed
  messenger's padding. The brief author read only its abstract. Do not describe it on the
  page beyond what you verify yourself; it is optional context, not part of this build.

---

## FACTS (write tests from these, not from your code)

1. **Setting** (paper, sections 1 and 3 as summarised in its introduction). The user's
   encryption code has been replaced. The replacement must (a) produce ciphertexts the honest
   decryptor decrypts correctly, and (b) be indistinguishable from the real code to a tester
   who knows the user's key. Whoever holds a separate subversion key gains the user's key.
2. **Base scheme used in this lab ("CTR$").** Ciphertext = IV ‖ AES-CTR_K(M), a fresh random
   16-byte IV as the initial counter block, counter incremented as a 128-bit big-endian
   integer. This is randomized and stateless, and it surfaces its IV.
3. **IV replacement** (section 4.1). On the first encryption only, the subverted code sets
   IV = E(K̃, K): one block-cipher call on the user's key under the subversion key. Later IVs
   are random. The holder of K̃ computes K = E⁻¹(K̃, IV) from the first ciphertext. It is done
   once (and so needs state) because a repeated IV would be visible. The paper assumes key
   and IV have the same length; with AES-128 keys and 16-byte IVs they do.
4. **Biased ciphertexts** (section 4.2). The subverted code keeps a counter. For the j-th
   ciphertext it draws coins until F(K̃, C ‖ j) equals bit j of K, where C is the ciphertext
   those coins produce and F is a PRF with one-bit output; the holder of K̃ evaluates F on
   each ciphertext and reads the key off, one bit per ciphertext, |K| ciphertexts in all,
   whatever the messages are. The paper calls this universal for randomized stateless schemes
   with at least about 7 bits of coins, proves undetectability for coin-injective schemes
   (CTR$ is one: different IVs give different ciphertexts), and notes the subverted code is
   stateful. (The paper's F also takes a user index; this lab has one user and omits it. Say
   so.)
5. **This lab's concrete choices** (the brief's, not the paper's; state them on the page):
   F(K̃, C, j) = least significant bit of the first byte of HMAC-SHA-256(K̃, C ‖ j), with j as
   a 4-byte big-endian integer and j counted from 0; bit j of K is taken most significant bit
   first, (K[j >> 3] >> (7 − (j & 7))) & 1; K̃ is 32 bytes for exhibit 4 and a separate
   16-byte AES key for exhibit 3.
6. **Unique ciphertexts** (section 5). A scheme has unique ciphertexts if, for each key,
   message, associated data and decryptor state, at most one ciphertext decrypts to that
   message. Such a scheme is deterministic (the converse is false). Theorem 4: a subversion
   of a unique-ciphertext scheme that keeps decryption correct gives the adversary advantage
   zero, because the subverted code is forced to output the same ciphertext as the real one.
7. **What the brief author measured** with a separate program (Python, `cryptography` library
   for AES, standard library HMAC), 15 November 2026:
   - 128 subverted ciphertexts always suffice for a 128-bit key; a second independent program
     recovered the full key in 300 of 300 trials with random messages of varying length.
   - Coins tried per ciphertext: mean 2.01 over 38,400 ciphertexts, largest 18 (geometric,
     mean 2).
   - Extracting "key bits" from 128 HONEST ciphertexts gives about half right by chance (67 of
     128 in the fixed vector of check D). That is the control.
   - With only c coin bits available, the subverter finds no suitable coin with probability
     2^−(2^c): measured 0.2465, 0.0576, 0.0034 for c = 1, 2, 3 (20,000 trials each) against
     0.25, 0.0625, 0.0039. For c = 7 it is 2^−128, which is the paper's "7 bits" remark.

---

## SCOPE

In scope, as exhibits in this order:

1. **The honest encryptor.** CTR$ with real AES; encrypt, decrypt, show the IV and the tests a
   careful user might run (round trip, no repeated IVs, byte histogram of IVs).
2. **Swap the code.** A switch replaces the encryptor. The learner's view (ciphertexts, the
   same tests) is unchanged; a second, clearly separated panel is "the holder of the
   subversion key".
3. **IV replacement.** One ciphertext; the second panel recovers the key from its first 16
   bytes and decrypts everything after.
4. **Biased ciphertexts.** The learner encrypts their own messages (or presses "encrypt 128");
   the second panel fills in the key one bit per ciphertext, with the coins-tried count per
   ciphertext shown. The control: the same extraction on honest ciphertexts, about half right.
5. **How little randomness it needs.** A coin budget of c bits (1 to 8): measured failure rate
   of the subverter against 2^−(2^c).
6. **A scheme with nothing to choose.** A deterministic, stateful, unique-ciphertext scheme
   built as the paper's section 5 describes (read it; the brief author expects a nonce-based
   authenticated scheme such as AES-GCM with the nonce taken from a counter both sides keep,
   but did not read that part). Show that the biased-ciphertext subverter has no coins to
   retry, and that any ciphertext other than the one honest output is rejected or decrypts to
   something else.

Non-goals (say so on the page and in the README): public-key (asymmetric) subversion keys;
the stateless variant from later work; subversion of signatures or key generation; any claim
that the statistical tests in exhibits 1 and 2 PROVE undetectability (they illustrate it; the
proof is the paper's and rests on F being a PRF); any claim about a real product.

---

## SECURITY / CORRECTNESS INVARIANTS

1. Every subverted ciphertext is decrypted by the HONEST decryptor and compared with its
   plaintext before it is displayed.
2. "Key recovered" is shown only after the recovered bytes are compared with the user's key.
3. The second panel's code receives ciphertexts and K̃ only (enforce by function signature).
4. The honest encryptor draws IVs from `crypto.getRandomValues`. The subverted encryptor draws
   its candidate coins from the same source in normal use; a coin source can be injected for
   the fixed test vector (check D) and for exhibit 5.
5. AES, HMAC and GCM are real: WebCrypto or an implementation that passes the vectors in
   check A. No truncated-round or toy cipher anywhere.
6. Rates in exhibit 5 are counted from runs, with the number of runs shown.

---

## ARCHITECTURE

Pure modules, no DOM: `ctr.ts` (base scheme), `block.ts` (single-block AES both directions),
`subvert-iv.ts`, `subvert-bias.ts`, `bigbrother.ts` (extraction only), `unique.ts`, `tests.ts`
(the user-side checks). WebCrypto has AES-CTR, AES-CBC, AES-GCM and HMAC but no raw
single-block call. Two honest routes for exhibit 3: (a) a small table-free or table-based AES
that passes check A in both directions; (b) WebCrypto AES-CBC: E_K(B) is the first block of
CBC-encrypting B under a zero IV, and D_K(c) is obtained by CBC-decrypting c ‖ x under a zero
IV, where x is the single block produced by CBC-encrypting the empty message under IV = c
(the brief author checked both identities by computation). State which route you took.

---

## UI AND VISUAL SEMANTICS

Follow §3. Two panels with different headings and a visible boundary: "What the user sees"
and "What the holder of the subversion key sees". Hex in tabular figures. The recovered key
fills in bit by bit as text, not by colour alone. The subverted state is announced in text
(for example a persistent status line), never only by a colour change.

---

## EDGE CASES (each fails closed and teaches via its message)

- Fewer than 128 ciphertexts in exhibit 4: the panel shows the bits known so far and says the
  key is not yet recovered.
- Coin budget exhausted in exhibit 5: reported as "no suitable coin"; the page does not emit
  a ciphertext with the wrong bit and call it a success.
- Empty message: allowed for CTR$ (the ciphertext is the IV alone); must still work.
- Wrong subversion key in the second panel: recovered bytes do not equal the key; verdict
  "not recovered".
- Counter overflow in the IV: an IV ending in ff bytes must carry correctly (check A).
- Exhibit 6 with decryptor state out of step: rejected.

---

## EXTENSION SEAMS (shape now, do not build)

A `Subversion` interface (encrypt + extract) so a stateless variant or a padding-based channel
could be added. A `BaseScheme` interface so CBC with random IV could sit beside CTR$. Name
these on the page as "not built here".

---

## ACCEPTANCE CHECKS — expected outcomes, derived independently of any implementation

**A. Primitives.** FIPS 197 Appendix C.1: key `000102030405060708090a0b0c0d0e0f`, block
`00112233445566778899aabbccddeeff` gives `69c4e0d86a7b0430d8cdb78070b4c55a`, and back.
NIST SP 800-38A F.5.1 (CTR-AES128, four blocks, initial counter
`f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff`, which carries into the next byte after the first
block): take the full vector from the NIST document; the ciphertext begins `874d6191b620e326`
and ends `792170a0f3009cee`. HMAC-SHA-256, RFC 4231 test case 2 (key "Jefe"): tag begins
`5bdcc146bf60754e`. An AES-GCM vector from the NIST or McGrew-Viega test set with more than
one block of plaintext for exhibit 6. Confirm each against its document.

**B. Round trip.** For 1,000 random keys, messages (lengths 0 to 100 bytes) and both
subversions: honest decryption of the subverted ciphertext equals the plaintext.

**C. IV replacement, fixed vector.** K = `000102030405060708090a0b0c0d0e0f`,
subversion AES key `2b7e151628aed2a6abf7158809cf4f3c`. The first IV is
`50fe67cc996d32b6da0937e99bafec60`, and the holder of the subversion key recovers K from it.
With message M_0 of check D the whole first ciphertext is
`50fe67cc996d32b6da0937e99bafec60d6e0b8f4f686d85cd4c2933608819536e83f1e686653b9c35ab9a9b895741c4e373b9aaea1a5f695c4df`.
The second ciphertext's IV is NOT a function of K (test: two runs differ).

**D. Biased ciphertexts, fixed vector** (computed by the brief author's separate program).
K as in C. K̃ = the 32 bytes `a0 a1 … bf`. Message j (j = 0 … 127) is the 42 ASCII bytes
`crypto-lab subverted-mode test vector #` followed by j as three decimal digits. Injected
coin source: the t-th candidate IV for ciphertext j (t = 0, 1, …) is the first 16 bytes of
SHA-256(ASCII "coins" ‖ j as 4 bytes big-endian ‖ t as 4 bytes big-endian). Expected:
- candidates tried for j = 0 … 15: 2, 1, 2, 1, 4, 2, 4, 1, 2, 2, 2, 1, 1, 1, 1, 1; total over
  all 128 ciphertexts 251; largest 8; 67 ciphertexts accepted their first candidate;
- ciphertext 0 =
  `e29fb8f21ebfbbf4a4f35e94880d982421a3aa1d1b6bed8930407544d9fc2cd315a432e1093e508f913fe461a0d1b9f80e5eda42d6fed9fbe33c`;
- ciphertext 127 =
  `8ef6e29072a3be52e78300554f6147de94eaeb8f6067f1a89d011d42648f9c3b4ca5936c236896af1acaa3590ff06a2b7bab52afaab9b1235827`;
- SHA-256 of the 128 ciphertexts concatenated in order =
  `b87845548f95d9dea8375cac6ce03401c3b5c72a566efeab5d98fe90e8787f8c`;
- extraction returns K exactly;
- control: the honest encryptor fed the first candidate (t = 0) for each j yields ciphertexts
  from which the same extraction gets 67 of 128 bits right.
These vectors pin the brief's choices in FACTS 5 (bit order, encoding of j, which HMAC bit).

**E. Statistics** (slow tests, tagged). Over at least 10,000 subverted ciphertexts with random
coins: mean candidates tried between 1.9 and 2.1. Coin budget: failure rate within
0.25 ± 0.02 for c = 1, 0.0625 ± 0.01 for c = 2, 0.0039 ± 0.003 for c = 3, at 20,000 trials
each. Honest-ciphertext control over 100 fresh keys: mean bits right between 60 and 68 of 128.

**F. Unique ciphertexts (exhibit 6).** For random key, message, associated data and state:
encrypting twice gives the same ciphertext; flipping any single bit of the ciphertext makes
the decryptor reject (test every bit position of at least one two-block ciphertext); the
biased-ciphertext subverter, given this scheme, reports that it has no coins to choose.
Whatever construction you take from section 5, also state its uniqueness argument in the
README in two or three sentences of your own.

**G. Mutations that must be killed (§4.1c, run from a script, each a concrete patch).**
(1) key bits taken least-significant-first; (2) j encoded as one byte instead of four;
(3) F reads the most significant bit of the HMAC byte; (4) the subverted encryptor accepts
the first candidate without testing F (round trips still pass; extraction must fail, and the
control test must not be the thing that hides it); (5) the counter j is not advanced, so the
same key bit is leaked every time; (6) IV replacement applied to every ciphertext (the
repeated-IV user test must then FAIL, which is the point of doing it once); (7) "key
recovered" set whenever 128 bits have been extracted, without comparing to the key (killed by
the wrong-subversion-key fixture); (8) counter-mode increment wraps at 64 bits (killed by
check A only if the vector's carry is exercised: add an IV of sixteen ff bytes with a
two-block message, expected value from an independent implementation in the test). A
surviving mutation is reported, not explained away.

**H. Fail-closed paths, each a NAMED test:** every item under EDGE CASES; invariant 3; a
subverted ciphertext that fails honest decryption is never displayed (inject a broken
encryptor in the test).

**I. Claims suite (§4.1b).** At minimum: every ciphertext on screen decrypts, in the test,
with WebCrypto and the key on screen, to the plaintext on screen; the recovered key on screen
equals the user key on screen; the user-side tests shown as passing are recomputed by the
test from the rendered ciphertexts (no repeated IV among those shown); the coins-tried
numbers shown sum to the total shown; stale verdicts are retired when the key, the mode or
the encryptor changes; the no-op guard; the `[hidden]` probe.

---

## NEGATIVE CLAIM (§4.1d)

Claim, scoped to what is on the page: **"Every test the user can run with their own key
passes, and that says nothing about whether the encryptor is leaking the key: for these 128
ciphertexts it has leaked all of it."**

Evidence fixture: exhibit 4 after 128 ciphertexts. All user-side checks report success
(round trip, no repeated IV, IV bytes unremarkable) and the verdict reads
`ALL USER CHECKS PASS — AND THE KEY HAS LEAKED`, with the negative-claim sentence visible in
that state and the second panel showing the recovered key equal to the user's key.

Bite fixture for mutation (7): the second panel is given a different K̃ (for instance the 32
bytes `c0 … df`). 128 bits are extracted, they are not the key, and the page must say the key
was not recovered. The three assertions and two bite tests are as §4.1d specifies.

---

## README NOTES

Follow §5. "What It Is" names the two attacks, the base scheme, the defence, and "not
production crypto — a teaching demo". "When to Use It" must include a "do NOT": do not treat
the page's statistical checks as a detector for subverted software. "What Can Go Wrong" is
the paper's lesson: unverifiable choice (random IVs, variable padding) is a channel.
"Real-World Usage": only what you can cite; where standards moved towards deterministic or
nonce-misuse-resistant designs, cite the document, do not attribute a motive it does not
state. "Build & Verify" states the test count, the standard vectors, the fixed subversion
vector's SHA-256, and the a11y gate. Credit the paper by title and authors with its ePrint
link; no links to PDF copies elsewhere.

---

## CARD METADATA TO REPORT BACK (for the catalog session; do not edit the catalog yourself)

Title: Subverted Cipher. Subtitle as above. Suggested categories: ATTACKS, SYMMETRIC (confirm
both exist in the catalog's CATEGORIES). Suggested level: intermediate. Chips: only what the
source implements (AES-CTR, HMAC-SHA-256, IV-replacement subversion, biased-ciphertext
subversion, and the exhibit 6 scheme by name). Accent #a3c4bc.

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
