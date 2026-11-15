/**
 * Exhibit 6 -- a scheme with nothing to choose.
 *
 * The construction is the paper's section 5, Theorem 6: a nonce-based AEAD
 * that is non-degenerate, made stateful by taking the nonce from a counter
 * both sides keep. Here that AEAD is AES-128-GCM (NIST SP 800-38D) through
 * WebCrypto, with a 96-bit nonce and a 128-bit tag.
 *
 * Three things are shown, each computed live:
 *   - determinism: the same key, message, associated data and state give
 *     byte-identical ciphertexts;
 *   - uniqueness in the only form a browser can demonstrate: every single-bit
 *     change to a ciphertext is rejected, so no second string decrypts to the
 *     message;
 *   - the subverter, handed this scheme, reporting that it has no coins.
 */
import { equal, hex, randomBytes, utf8 } from '../subverted/bytes.js';
import { BiasedEncryptor } from '../subverted/subvert-bias.js';
import {
  gcmDecrypt,
  nonceFromCounter,
  UniqueDecryptor,
  UniqueEncryptor,
  uniqueAsBaseScheme,
} from '../subverted/unique.js';
import { button, clear, code, disclosure, field, fmt, h, learnerCheck, note, panelIntro, para, verdict } from './dom.js';

const DEFAULT_MESSAGE = 'The same message, encrypted twice, under the same state.';

export function renderUniquePanel(root: HTMLElement): void {
  let key = randomBytes(16);
  const ad = utf8('to:accounts');

  const determinismBox = h('div', { class: 'output', id: 'unique-determinism' });
  const tamperBox = h('div', { class: 'output', id: 'unique-tamper' });
  const stateBox = h('div', { class: 'output', id: 'unique-state' });
  const subverterBox = h('div', { class: 'output', id: 'unique-subverter' });
  const stateLine = h('p', { class: 'state-row', id: 'unique-counters', role: 'status', 'aria-live': 'polite' });

  const msgInput = h('textarea', {
    id: 'unique-msg',
    class: 'msg-input',
    rows: 2,
    'aria-label': 'Message to encrypt',
  }) as HTMLTextAreaElement;
  msgInput.value = DEFAULT_MESSAGE;

  let sender = new UniqueEncryptor(key);
  let receiver = new UniqueDecryptor(key);

  function renderCounters(): void {
    clear(stateLine);
    stateLine.append(
      h('span', {}, 'Sender counter σ = ', h('code', { id: 'unique-sigma' }, String(sender.state))),
      h('span', {}, 'Receiver counter τ = ', h('code', { id: 'unique-tau' }, String(receiver.state))),
      h('span', {}, 'Next nonce = ', h('code', {}, hex(nonceFromCounter(sender.state)))),
    );
  }

  async function runDeterminism(): Promise<void> {
    const msg = utf8(msgInput.value);
    // Two encryptors at the same state: the paper's E* is deterministic given
    // (key, message, associated data, state), so these must agree.
    const a = new UniqueEncryptor(key);
    const b = new UniqueEncryptor(key);
    a.seek(sender.state);
    b.seek(sender.state);
    const ca = await a.encrypt(msg, ad);
    const cb = await b.encrypt(msg, ad);
    const same = equal(ca.ct, cb.ct);
    clear(determinismBox);
    determinismBox.append(
      field('Encryption 1', hex(ca.ct), { sub: `nonce ${hex(ca.nonce)}` }),
      field('Encryption 2', hex(cb.ct), { sub: `same key, message, associated data and counter` }),
      verdict(
        same ? 'pass' : 'fail',
        same ? 'BYTE FOR BYTE IDENTICAL — THERE IS NOTHING TO CHOOSE' : 'THE TWO CIPHERTEXTS DIFFER',
        'unique-determinism',
        same
          ? `Both ${fmt(ca.ct.length)} bytes, compared position by position. No randomness enters: the nonce is the counter.`
          : 'Something in this scheme is still drawing randomness.',
      ),
    );
  }

  async function runTamper(): Promise<void> {
    const msg = utf8('two blocks of plaintext, thirty-two bytes.');
    const enc = new UniqueEncryptor(key);
    const { ct, counter, nonce } = await enc.encrypt(msg, ad);
    let rejected = 0;
    // Every single-bit change, tested against the real decryptor. For a
    // ciphertext of this size that is a few hundred decryptions, which is the
    // whole point: not one of them is a second ciphertext for this message.
    for (let bit = 0; bit < ct.length * 8; bit++) {
      const flipped = Uint8Array.from(ct);
      flipped[bit >> 3]! ^= 1 << (bit & 7);
      if ((await gcmDecrypt(key, nonce, ad, flipped)) === null) rejected++;
    }
    const total = ct.length * 8;
    const back = await gcmDecrypt(key, nonce, ad, ct);
    clear(tamperBox);
    tamperBox.append(
      field('Ciphertext under test', hex(ct), { sub: `${ct.length} bytes at counter ${counter}` }),
      verdict(
        back !== null && equal(back, msg) ? 'pass' : 'fail',
        back !== null && equal(back, msg) ? 'THE UNTOUCHED CIPHERTEXT DECRYPTS' : 'THE UNTOUCHED CIPHERTEXT DOES NOT DECRYPT',
        'unique-roundtrip',
        'The baseline, so the rejections below mean something.',
      ),
      verdict(
        rejected === total ? 'pass' : 'fail',
        rejected === total
          ? `ALL ${fmt(total)} SINGLE-BIT CHANGES REJECTED`
          : `${fmt(total - rejected)} OF ${fmt(total)} SINGLE-BIT CHANGES WERE ACCEPTED`,
        'unique-tamper',
        rejected === total
          ? 'Every one-bit neighbour of this ciphertext fails authentication, so none of them is a second ciphertext for this message.'
          : 'A neighbouring string decrypts, so the ciphertext is not unique.',
      ),
    );
  }

  async function runState(): Promise<void> {
    const s = new UniqueEncryptor(key);
    const r = new UniqueDecryptor(key);
    const first = await s.encrypt(utf8('message zero'), ad);
    const second = await s.encrypt(utf8('message one'), ad);
    // Deliver the second first: the receiver is at counter 0 and will only try
    // the nonce it holds, so this is a ciphertext under the wrong nonce.
    const early = await r.decrypt(second.ct, ad);
    const inOrder0 = await r.decrypt(first.ct, ad);
    const inOrder1 = await r.decrypt(second.ct, ad);
    const replay = await r.decrypt(first.ct, ad);
    clear(stateBox);
    stateBox.append(
      verdict(
        early.ok ? 'fail' : 'pass',
        early.ok ? 'OUT-OF-ORDER CIPHERTEXT ACCEPTED' : 'OUT-OF-ORDER CIPHERTEXT REJECTED',
        'unique-outoforder',
        `The receiver was at τ = 0 and the ciphertext was made at σ = 1. Its counter did not move: τ = ${early.counter}.`,
      ),
      verdict(
        inOrder0.ok && inOrder1.ok ? 'pass' : 'fail',
        inOrder0.ok && inOrder1.ok ? 'IN ORDER, BOTH DECRYPT' : 'IN ORDER, THEY DO NOT BOTH DECRYPT',
        'unique-inorder',
        'The receiver advances one counter per accepted ciphertext, which is what makes the nonce agree.',
      ),
      verdict(
        replay.ok ? 'fail' : 'pass',
        replay.ok ? 'A REPLAY WAS ACCEPTED' : 'A REPLAY REJECTED',
        'unique-replay',
        'The first ciphertext, sent again, is now a ciphertext under a nonce the receiver has passed.',
      ),
    );
  }

  async function runSubverter(): Promise<void> {
    const enc = new UniqueEncryptor(key);
    const honest = new UniqueEncryptor(key);
    const scheme = uniqueAsBaseScheme(enc, ad);
    const sub = new BiasedEncryptor(randomBytes(32), scheme);
    const msg = utf8(msgInput.value);
    const r = await sub.encrypt(key, msg);
    const honestCt = (await honest.encrypt(msg, ad)).ct;
    const forced = !r.ok && r.ct !== undefined && equal(r.ct, honestCt);
    clear(subverterBox);
    subverterBox.append(
      field('Coin bytes this scheme offers the subverter', String(scheme.coinBytes), { mono: false }),
      field('What the subverted code emitted', r.ok ? hex(r.ct) : r.ct ? hex(r.ct) : '(nothing)'),
      field('What the honest code emits', hex(honestCt)),
      verdict(
        !r.ok && forced ? 'pass' : 'fail',
        !r.ok && forced
          ? 'NO COINS TO CHOOSE — THE SUBVERTER IS FORCED TO EMIT THE HONEST CIPHERTEXT'
          : 'THE SUBVERTER FOUND ROOM TO CHOOSE',
        'unique-nocoins',
        !r.ok && forced
          ? `It reports "${r.reason}" after ${r.tried} candidate, because there is only one. The bytes it emitted are compared here with the honest encryptor's and are identical.`
          : 'Something in this scheme still gives the subverted code a choice.',
      ),
    );
  }

  async function runAll(): Promise<void> {
    renderCounters();
    await runDeterminism();
    await runTamper();
    await runState();
    await runSubverter();
  }

  root.append(
    panelIntro(
      'A scheme with nothing to choose',
      'Both attacks live in the same place: the encryptor picks bytes nobody can check. Take that away and there is nowhere left to hide a bit.',
      para(
        'A scheme has ',
        code('unique ciphertexts'),
        ' when, for each key, message, associated data and receiver state, at most one string decrypts to that message. The paper proves (Theorem 4) that a subversion of such a scheme which still decrypts correctly has advantage exactly zero — not small, zero — because the subverted code is forced to output the same ciphertext the honest code would have.',
      ),
      para(
        'This exhibit builds the paper\'s section 5 construction from nonce-based schemes (Theorem 6): take a non-degenerate nonce-based AEAD and make it stateful by using a counter as the nonce on both sides. The AEAD here is AES-128-GCM with a 96-bit nonce and a 128-bit tag. Deterministic, stateful, and nothing is drawn at random.',
      ),
    ),
    h(
      'div',
      { class: 'controls' },
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'unique-msg' }, 'Message'),
        msgInput,
        h('p', { class: 'help' }, `Associated data is fixed at "${new TextDecoder().decode(ad)}" so there is one thing less to vary.`),
      ),
      h(
        'div',
        { class: 'input-row' },
        button('Run every check again', () => void runAll(), { kind: 'primary', id: 'unique-run' }),
        button('Advance the sender\'s counter', () => {
          sender.seek(sender.state + 1);
          void runAll();
        }, { id: 'unique-advance' }),
        button('New key', () => {
          key = randomBytes(16);
          sender = new UniqueEncryptor(key);
          receiver = new UniqueDecryptor(key);
          void runAll();
        }, { id: 'unique-newkey' }),
      ),
      stateLine,
    ),
    h('div', { class: 'section-block' }, h('h3', {}, '1 · Encrypting twice gives the same bytes'), determinismBox),
    h('div', { class: 'section-block' }, h('h3', {}, '2 · No neighbouring string is a second ciphertext for the message'), tamperBox),
    h('div', { class: 'section-block' }, h('h3', {}, '3 · The counters have to agree'), stateBox),
    h('div', { class: 'section-block' }, h('h3', {}, '4 · The subverter, handed this scheme'), subverterBox),
    learnerCheck(
      'Deterministic encryption has unique ciphertexts. True or false?',
      [
        { label: 'True — if there is one output there is one ciphertext', correct: false },
        { label: 'False — determinism fixes what the ENCRYPTOR emits, not what the DECRYPTOR will accept', correct: true },
        { label: 'True, but only for authenticated schemes', correct: false },
      ],
      'The paper is careful about this and so is the implication: unique ciphertexts imply deterministic, and the converse is false. A deterministic scheme produces one ciphertext per message, but some OTHER string may also decrypt to that message, and a subverted encryptor is free to emit that one instead. Uniqueness is a property of the decryptor\'s acceptance set. It is the same distinction as between deterministic and unique signatures.',
    ),
    disclosure(
      'Why AES-GCM with a counter nonce has unique ciphertexts',
      'Fix the key and the nonce. The counter-mode keystream is then fixed, so the only ciphertext body that decrypts to a given message is that message XOR the keystream — one string, not a choice. The tag is a deterministic function of the key, nonce, associated data and that body (GHASH over them, then one more block-cipher call), so there is exactly one tag the receiver will accept with it. One body, one tag: the acceptance set has one element.',
      'Check 2 above is the browser-sized demonstration of that: every single-bit neighbour of a real ciphertext is rejected. It is a demonstration, not the proof — the argument above is the proof, and it assumes GCM\'s authentication holds.',
      'The paper gives a second construction as well, an encode-then-encipher scheme built on a variable-input-length pseudorandom permutation (Theorem 5). It is not built here; it needs a wide-block PRP, which is two passes and slower than the nonce-based route.',
    ),
    note(
      'caveat',
      'What this costs: the sender and receiver must keep counters and stay in step, which is exactly what exhibit 3 shows going wrong when they do not. The paper is explicit that this is the price — stateful, deterministic encryption — and that it is not free in protocols built on top.',
    ),
    note(
      'info',
      'Not claimed here: that AES-GCM as deployed is surveillance-resistant. TLS 1.2 and IPsec let an implementation choose the explicit nonce freely, which the paper notes leaves those deployments open to IV replacement; the construction on this page is the one that pins the nonce to a counter.',
    ),
  );

  void runAll();
}
