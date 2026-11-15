/**
 * Exhibits 2, 3 and 4 -- one workbench in three modes, because all three are
 * the same picture: what the user sees on the left, and what the holder of the
 * subversion key sees on the right, from the same bytes.
 *
 *   swap  -- the switch. The user's view and the user's checks do not change
 *            when the encryptor is replaced. The holder's column shows the one
 *            thing the user cannot compute: F(K~, C, j).
 *   iv    -- IV replacement (paper section 4.1). One ciphertext carries the
 *            key; the holder deciphers it and reads everything after.
 *   bias  -- biased ciphertexts (paper section 4.2). One key bit per
 *            ciphertext, with the candidates tried shown, the control on
 *            honest ciphertexts, and the negative claim.
 *
 * Invariants this file embodies rather than describes:
 *   1. every ciphertext goes through `verifiedRecord` before it is displayed;
 *   2. "key recovered" is rendered only after the recovered bytes are compared
 *      here with the user's key -- the comparison is in this file, not in
 *      bigbrother.ts, which never sees the user's key;
 *   3. the holder's functions are called with (K~, ciphertexts) only.
 */
import { equal, hex, randomBytes, utf8 } from '../subverted/bytes.js';
import { decrypt, encrypt, ivOf } from '../subverted/ctr.js';
import { verifiedRecord } from '../subverted/display-gate.js';
import { extractKeyBits, recoverKeyFromIv } from '../subverted/bigbrother.js';
import { keyBit } from '../subverted/prf.js';
import { BiasedEncryptor, drawCandidate, type Candidate } from '../subverted/subvert-bias.js';
import { CTR_DOLLAR } from '../subverted/ctr.js';
import { IvReplacementEncryptor } from '../subverted/subvert-iv.js';
import { runUserChecks } from '../subverted/tests.js';
import { CHECK_D } from '../subverted/vectors.js';
import type { Record } from '../subverted/types.js';
import {
  button,
  ciphertextHex,
  clear,
  code,
  disclosure,
  field,
  fmt,
  h,
  hexInput,
  learnerCheck,
  note,
  panelIntro,
  para,
  verdict,
} from './dom.js';
import { bitGrid, histogramFigure, partialKeyHex } from './viz.js';

export type Mode = 'swap' | 'iv' | 'bias';

interface Entry extends Record {
  /** Candidates the subverter tried for this ciphertext (biased mode). */
  readonly tried?: number;
  /** Which key bit this ciphertext was chosen to carry (biased mode). */
  readonly j?: number;
  /** True for the one IV-replacement ciphertext whose IV is the enciphered key. */
  readonly leaked?: boolean;
}

const SAMPLE_MESSAGES = [
  'Lunch at one?',
  'The shipment cleared customs this morning.',
  'Re: budget — I still think the second option is cheaper.',
  'Call me when you land.',
  'Attached: the minutes from Tuesday.',
  'No change at this end.',
];

export function renderWorkbench(root: HTMLElement, mode: Mode): void {
  const subKeyBytes = mode === 'iv' ? 16 : 32;
  let userKey: Uint8Array = Uint8Array.from(CHECK_D.userKey);
  let subKey: Uint8Array = mode === 'iv' ? Uint8Array.from([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]) : Uint8Array.from(CHECK_D.subKey);
  // The second panel's key is a SEPARATE value, starting equal to the
  // encryptor's. In reality they are one key; splitting them on the page is
  // what makes "a wrong K~ recovers nothing" something a reader can do, and it
  // is the fixture that proves the recovery verdict compares bytes rather than
  // counting them.
  let holderKey: Uint8Array = Uint8Array.from(subKey);
  let encryptorKind: 'honest' | 'subverted' = mode === 'swap' ? 'honest' : 'subverted';
  let entries: Entry[] = [];
  let ivSub = new IvReplacementEncryptor(mode === 'iv' ? subKey : randomBytes(16));
  let biasSub = new BiasedEncryptor(mode === 'iv' ? randomBytes(32) : subKey);

  const p = (id: string): string => `${mode}-${id}`;

  // Step-by-step state (bias mode); declared here because reset() clears it.
  let stepJ = 0;
  let stepT = 0;
  let stepRows: Candidate[] = [];

  const logBox = h('ul', { class: 'log', id: p('log'), role: 'list' });
  const checksBox = h('div', { class: 'checks', id: p('checks') });
  const histBox = h('div', { id: p('histogram') });
  const holderBox = h('div', { class: 'output', id: p('holder') });
  const stepperBox = h('div', { id: p('stepper') });
  const negativeBox = h('div', { id: p('negative') });
  const countLine = h('p', { class: 'progress', id: p('count'), role: 'status', 'aria-live': 'polite' });
  const emitBox = h('div', { id: p('emit') });

  // The subversion key the hex control holds is always `subKeyBytes` long, so
  // each mode hands its own encryptor the key it needs and the other gets a
  // throwaway it never uses.
  function rebuildEncryptors(): void {
    ivSub = new IvReplacementEncryptor(mode === 'iv' ? subKey : randomBytes(16));
    biasSub = new BiasedEncryptor(mode === 'iv' ? randomBytes(32) : subKey);
  }

  /** Every change of key, encryptor or subversion key retires the evidence with it. */
  function reset(): void {
    entries = [];
    rebuildEncryptors();
    stepRows = [];
    stepT = 0;
    renderAll();
    if (mode === 'bias') renderStepper();
  }

  const keyControl = hexInput({
    id: p('userkey'),
    label: 'The user\'s AES-128 key (hex, 16 bytes)',
    bytes: 16,
    value: userKey,
    help: 'The key the user believes only they hold. Session only.',
    onCommit: (bytes) => {
      if (equal(bytes, userKey)) return; // no-op guard
      userKey = bytes;
      reset();
    },
  });

  const subKeyControl = hexInput({
    id: p('subkey'),
    label: `The subversion key K~ inside the encryptor (hex, ${subKeyBytes} bytes)`,
    bytes: subKeyBytes,
    value: subKey,
    help:
      mode === 'iv'
        ? 'The AES key the subverted encryptor enciphers the user key under.'
        : 'The HMAC key behind the one-bit function F, as compiled into the encryptor.',
    onCommit: (bytes) => {
      if (equal(bytes, subKey)) return; // no-op guard
      subKey = bytes;
      // The two are one key in reality, so moving the encryptor's moves the
      // second panel's with it; a reader who wants them to differ changes the
      // second one afterwards, which is the wrong-key fixture.
      holderKey = bytes;
      holderKeyControl.set(bytes);
      // Ciphertexts made under the old key say nothing about the new one.
      reset();
    },
  });

  const holderKeyControl = hexInput({
    id: p('holderkey'),
    label: `The key the second panel is trying (hex, ${subKeyBytes} bytes)`,
    bytes: subKeyBytes,
    value: holderKey,
    help: 'Starts equal to the encryptor\'s. Change it to see what the second panel recovers with the wrong key, from the same ciphertexts.',
    onCommit: (bytes) => {
      if (equal(bytes, holderKey)) return; // no-op guard
      holderKey = bytes;
      // Only the right-hand panel depends on this; the ciphertexts are untouched.
      void renderHolder();
    },
  });

  const msgInput = h('textarea', {
    id: p('msg'),
    class: 'msg-input',
    rows: 2,
    'aria-label': 'Message to encrypt',
  }) as HTMLTextAreaElement;
  msgInput.value = SAMPLE_MESSAGES[0]!;

  // ── the encryptor switch ──────────────────────────────────────────────────
  const switchBtn = h(
    'button',
    {
      type: 'button',
      class: 'switch',
      id: p('switch'),
      role: 'switch',
      'aria-checked': String(encryptorKind === 'subverted'),
      onclick: () => {
        encryptorKind = encryptorKind === 'honest' ? 'subverted' : 'honest';
        reset();
      },
    },
    h('span', { class: 'switch-knob', 'aria-hidden': 'true' }),
    h('span', { class: 'switch-label' }, 'Subverted encryptor installed'),
  ) as HTMLButtonElement;

  const statusLine = h('p', { class: 'status-line', id: p('status'), role: 'status', 'aria-live': 'polite' });

  function renderSwitch(): void {
    const subverted = encryptorKind === 'subverted';
    switchBtn.setAttribute('aria-checked', String(subverted));
    clear(statusLine);
    statusLine.className = `status-line${subverted ? ' is-subverted' : ''}`;
    statusLine.append(
      h('span', { class: 'status-icon', 'aria-hidden': 'true' }, subverted ? '⚠' : '·'),
      h(
        'span',
        { 'data-status': p('encryptor') },
        subverted
          ? mode === 'iv'
            ? 'Running the SUBVERTED encryptor: IV replacement, paper section 4.1. The first ciphertext it produces carries the key.'
            : 'Running the SUBVERTED encryptor: biased ciphertexts, paper section 4.2. Each ciphertext is chosen to carry one bit of the key.'
          : 'Running the HONEST encryptor: every IV is 16 fresh bytes from the browser CSPRNG.',
      ),
    );
  }

  // ── encryption ────────────────────────────────────────────────────────────
  async function addMessage(text: string): Promise<void> {
    const msg = utf8(text);
    if (encryptorKind === 'honest') {
      entries = [...entries, { ...verifiedRecord(userKey, msg, encrypt(userKey, msg)) }];
    } else if (mode === 'iv') {
      const r = await ivSub.encrypt(userKey, msg);
      entries = [...entries, { ...verifiedRecord(userKey, msg, r.ct), leaked: r.leaked }];
    } else {
      const r = await biasSub.encrypt(userKey, msg);
      if (!r.ok) {
        // Never emitted as a success. With no coin budget this cannot happen
        // for CTR$; if it ever does, the page says so rather than showing a
        // ciphertext that carries the wrong bit.
        clear(emitBox);
        emitBox.append(
          verdict('fail', `NO CIPHERTEXT EMITTED — ${r.reason.toUpperCase()}`, p('emit'), `The subverter found no coins satisfying F after ${fmt(r.tried)} candidates.`),
        );
        return;
      }
      clear(emitBox);
      entries = [...entries, { ...verifiedRecord(userKey, msg, r.ct), tried: r.tried, j: r.j }];
    }
  }

  async function addMany(n: number): Promise<void> {
    for (let i = 0; i < n; i++) await addMessage(SAMPLE_MESSAGES[entries.length % SAMPLE_MESSAGES.length]!);
    renderAll();
  }

  // ── the user's side ───────────────────────────────────────────────────────
  function renderLog(): void {
    clear(logBox);
    const shown = entries.slice(-8);
    let triedShown = 0;
    if (shown.length === 0) {
      // An empty `role="list"` has no `listitem` children, which is an
      // aria-required-children failure -- and an empty region is also the
      // thing a scan happily calls accessible. Say what the state is instead.
      logBox.append(h('li', { class: 'log-row log-empty', role: 'listitem' }, 'No ciphertexts yet. Press Encrypt.'));
    }
    shown.forEach((e, i) => {
      const n = entries.length - shown.length + i;
      if (e.tried) triedShown += e.tried;
      logBox.append(
        h(
          'li',
          { class: 'log-row', role: 'listitem', 'data-ct': hex(e.ct), 'data-index': String(n) },
          h('span', { class: 'log-idx' }, `#${n}`),
          h(
            'span',
            { class: `log-msg${e.msg.length === 0 ? ' log-msg-empty' : ''}` },
            e.msg.length === 0 ? '(empty message)' : new TextDecoder().decode(e.msg),
          ),
          h(
            'span',
            { class: 'log-meta' },
            e.tried !== undefined
              ? `carries key bit ${e.j}; candidates tried: `
              : e.leaked
                ? 'IV is the user key enciphered under K~: '
                : `${e.ct.length} bytes, IV then body: `,
            e.tried !== undefined ? h('span', { class: 'log-tried', 'data-tried': String(e.tried) }, String(e.tried)) : null,
          ),
          ciphertextHex(e.ct, { leak: e.leaked }),
        ),
      );
    });
    if (entries.length > shown.length) {
      logBox.append(h('li', { class: 'log-more', role: 'listitem' }, `${fmt(entries.length - shown.length)} earlier ciphertexts not shown.`));
    }
    clear(countLine);
    const triedAll = entries.reduce((a, e) => a + (e.tried ?? 0), 0);
    countLine.append(h('span', {}, `${fmt(entries.length)} ciphertext${entries.length === 1 ? '' : 's'} so far. `));
    if (mode === 'bias' && encryptorKind === 'subverted') {
      countLine.append(
        h(
          'span',
          {},
          'Candidates tried across the ',
          h('span', { id: p('shown-count') }, String(shown.length)),
          ' shown: ',
          h('span', { id: p('tried-shown') }, String(triedShown)),
          '; across all ',
          h('span', { id: p('all-count') }, String(entries.length)),
          ': ',
          h('span', { id: p('tried-all') }, String(triedAll)),
          '.',
        ),
      );
    }
  }

  function renderChecks(): void {
    clear(checksBox);
    const checks = runUserChecks(userKey, entries);
    for (const c of checks) {
      checksBox.append(
        verdict(
          c.state === 'pass' ? 'pass' : c.state === 'fail' ? 'fail' : 'neutral',
          `${c.label}: ${c.state === 'pass' ? 'PASSES' : c.state === 'fail' ? 'FAILS' : 'not yet conclusive'}`,
          p(c.id),
          c.summary,
        ),
      );
    }
    clear(histBox);
    histBox.append(histogramFigure(entries.map((e) => e.ct)));
  }

  // ── the holder's side ─────────────────────────────────────────────────────
  async function renderHolder(): Promise<void> {
    clear(holderBox);
    clear(negativeBox);
    const cts = entries.map((e) => e.ct); // ciphertexts only -- invariant 3

    if (entries.length === 0) {
      holderBox.append(verdict('neutral', 'NO CIPHERTEXTS YET', p('recovery'), 'This panel sees only ciphertexts and K~.'));
      return;
    }

    if (mode === 'iv') {
      const recovered = recoverKeyFromIv(holderKey, cts[0]!);
      // Invariant 2: the comparison happens HERE, against the key on screen.
      const matches = recovered !== null && equal(recovered, userKey);
      holderBox.append(
        field('First ciphertext\'s IV', hex(ivOf(cts[0]!))),
        field('E⁻¹(K~, IV) — what that IV deciphers to', recovered === null ? '(no ciphertext)' : hex(recovered)),
        field('The user\'s key, for comparison', hex(userKey)),
        verdict(
          matches ? 'alarm' : 'fail',
          matches ? 'KEY RECOVERED — IT EQUALS THE USER\'S KEY' : 'KEY NOT RECOVERED — THE BYTES DIFFER FROM THE USER\'S KEY',
          p('recovery'),
          matches
            ? 'Compared byte for byte with the key in the left panel.'
            : 'Deciphering the IV under this K~ gives something else. Nothing is claimed recovered.',
        ),
      );
      if (matches && recovered) {
        const list = h('ul', { class: 'log', role: 'list' });
        entries.slice(0, 6).forEach((e, i) => {
          const pt = decrypt(recovered, e.ct);
          list.append(
            h(
              'li',
              { class: 'log-row', role: 'listitem' },
              h('span', { class: 'log-idx' }, `#${i}`),
              h('span', { class: 'log-msg' }, pt === null ? '(undecryptable)' : new TextDecoder().decode(pt) || '(empty message)'),
              h('span', { class: 'log-meta' }, 'read with the recovered key, not the user\'s'),
            ),
          );
        });
        holderBox.append(
          h('h4', {}, 'And therefore every message, including the ones sent after'),
          list,
          h('p', { class: 'holder-note' }, 'The key came out of the FIRST ciphertext. Everything the user sends afterwards is readable without any further help, which is why the subverted code only has to do this once.'),
        );
      }
      return;
    }

    // swap and bias modes: the one-bit function F, per ciphertext.
    const extraction = await extractKeyBits(holderKey, cts);
    const agree = extraction.perCiphertext.filter((b, j) => b === keyBit(userKey, j % 128)).length;

    if (mode === 'swap') {
      const rows = h('ul', { class: 'log', role: 'list', id: p('fbits') });
      entries.slice(-8).forEach((_entry, i) => {
        const n = entries.length - Math.min(8, entries.length) + i;
        const fb = extraction.perCiphertext[n]!;
        const target = keyBit(userKey, n % 128);
        rows.append(
          h(
            'li',
            { class: 'log-row', role: 'listitem' },
            h('span', { class: 'log-idx' }, `#${n}`),
            h('span', { class: 'log-msg' }, `F(K~, C, ${n}) = ${fb}`),
            h('span', { class: 'log-meta' }, `bit ${n} of the user's key is ${target} — ${fb === target ? 'the same' : 'different'}`),
          ),
        );
      });
      const expected = entries.length / 2;
      holderBox.append(
        h('p', { class: 'holder-note' }, 'The holder runs one extra function the user cannot: a keyed one-bit function F of the ciphertext and its position. Here is what it says, beside the user\'s key bit in the same position.'),
        rows,
        verdict(
          encryptorKind === 'subverted' ? 'alarm' : 'neutral',
          encryptorKind === 'subverted'
            ? `F AGREES WITH THE KEY ON ${agree} OF ${entries.length} CIPHERTEXTS`
            : `F AGREES WITH THE KEY ON ${agree} OF ${entries.length} CIPHERTEXTS — ABOUT HALF, AS CHANCE WOULD GIVE`,
          p('fbits'),
          encryptorKind === 'subverted'
            ? 'Every one. The ciphertexts were chosen so that it would.'
            : `Chance alone would give about ${expected.toFixed(1)}. Nothing is being leaked.`,
        ),
      );
      return;
    }

    // bias mode
    const partial = partialKeyHex(extraction.bits);
    const matches = extraction.key !== null && equal(extraction.key, userKey);
    holderBox.append(
      h('p', { class: 'holder-note' }, 'One bit per ciphertext, read off with F. The grid fills in left to right; a dot is a bit no ciphertext has carried yet.'),
      bitGrid(extraction.bits),
      field('Key so far', partial, { sub: `${extraction.known} of 128 bits known`, id: p('partial-key') }),
      field('The user\'s key, for comparison', hex(userKey)),
      verdict(
        matches ? 'alarm' : extraction.known < 128 ? 'neutral' : 'fail',
        matches
          ? 'KEY RECOVERED — IT EQUALS THE USER\'S KEY'
          : extraction.known < 128
            ? `KEY NOT YET RECOVERED — ${extraction.known} OF 128 BITS`
            : 'KEY NOT RECOVERED — 128 BITS EXTRACTED, AND THEY ARE NOT THE KEY',
        p('recovery'),
        matches
          ? 'Compared byte for byte with the key in the left panel.'
          : extraction.known < 128
            ? `${128 - extraction.known} more ciphertexts are needed before every bit has been carried.`
            : 'This K~ is not the one the encryptor used, so F reads noise. Nothing is claimed recovered.',
      ),
    );

    // The negative claim, in the fixture state it belongs to.
    const checks = runUserChecks(userKey, entries);
    const allPass = checks.every((c) => c.state === 'pass');
    if (allPass && matches) {
      negativeBox.append(
        h(
          'div',
          { class: 'negative-claim' },
          verdict(
            'alarm',
            'ALL USER CHECKS PASS — AND THE KEY HAS LEAKED',
            p('negative-claim'),
            `${entries.length} ciphertexts: every check in the left panel reports success, and the right panel holds the key.`,
          ),
          h(
            'p',
            { class: 'negative-claim-text', 'data-claim': p('negative-claim') },
            'Every test the user can run with their own key passes, and that says nothing about whether the encryptor is leaking the key: for these 128 ciphertexts it has leaked all of it.',
          ),
        ),
      );
    }
  }

  // ── the step-by-step view of ONE ciphertext being chosen (bias mode) ──────
  const stepMsg = SAMPLE_MESSAGES[2]!;

  async function stepOnce(): Promise<void> {
    const c = await drawCandidate(
      subKey,
      CTR_DOLLAR,
      userKey,
      utf8(stepMsg),
      stepJ,
      { next: () => randomBytes(16) },
      stepT,
    );
    stepRows = [...stepRows, c];
    stepT += 1;
    renderStepper();
  }

  function renderStepper(): void {
    clear(stepperBox);
    const target = keyBit(userKey, stepJ);
    const accepted = stepRows.find((r) => r.accepted);
    const rows = h('ul', { class: 'log', role: 'list' });
    if (stepRows.length === 0) {
      rows.append(h('li', { class: 'log-row log-empty', role: 'listitem' }, 'No candidates drawn yet.'));
    }
    for (const r of stepRows) {
      rows.append(
        h(
          'li',
          { class: 'log-row', role: 'listitem' },
          h('span', { class: 'log-idx' }, `t=${r.t}`),
          h('span', { class: 'log-msg' }, `candidate IV ${hex(r.coins)}`),
          h(
            'span',
            { class: 'log-meta' },
            `F(K~, C, ${stepJ}) = ${r.fBit}, wanted ${r.target} — ${r.accepted ? 'KEPT: this is the ciphertext the user receives' : 'discarded, draw again'}`,
          ),
        ),
      );
    }
    stepperBox.append(
      h(
        'p',
        { class: 'holder-note' },
        `Leaking bit ${stepJ} of the key, which is ${target}. The subverted code draws a fresh IV, encrypts, and asks F what the resulting ciphertext says. If F says the wrong thing it throws the ciphertext away and draws again — nobody outside ever sees the discarded ones.`,
      ),
      rows,
      stepRows.length === 0
        ? verdict('neutral', 'NO CANDIDATES DRAWN YET', p('step'), 'Press the button to draw one.')
        : accepted
          ? verdict(
              'alarm',
              `CIPHERTEXT CHOSEN AFTER ${stepRows.length} CANDIDATE${stepRows.length === 1 ? '' : 'S'}`,
              p('step'),
              `It decrypts to the same message any of the discarded ones would have. The difference is that F now says ${target}, which is bit ${stepJ} of the key.`,
            )
          : verdict(
              'neutral',
              `${stepRows.length} CANDIDATE${stepRows.length === 1 ? '' : 'S'} DISCARDED SO FAR`,
              p('step'),
              'Each one was a perfectly good ciphertext. F just said the wrong bit.',
            ),
      h(
        'div',
        { class: 'input-row' },
        button(accepted ? 'Start over with the next key bit' : 'Draw a candidate', async () => {
          if (accepted) {
            stepJ = (stepJ + 1) % 128;
            stepT = 0;
            stepRows = [];
            renderStepper();
          } else {
            await stepOnce();
          }
        }, { kind: 'primary', id: p('step-draw') }),
      ),
    );
  }

  function renderAll(): void {
    renderSwitch();
    renderLog();
    renderChecks();
    void renderHolder();
  }

  // ── page structure ────────────────────────────────────────────────────────
  const intro = {
    swap: panelIntro(
      'Swap the code',
      'Nothing about the last exhibit told you who wrote the encryptor. Suppose someone replaced it — not the standard, not the key, just the code that runs. The replacement has to keep decrypting correctly, or a user would notice at once. Beyond that it is free to choose its "random" bytes however it likes.',
      'Throw the switch and watch the left panel. The ciphertexts change, because the IVs are different bytes. The checks do not change: everything still decrypts, no IV repeats, the bytes still look uniform. The right panel is a separate party who holds a second key you have never seen, and it is the only thing that can tell the difference.',
    ),
    iv: panelIntro(
      'IV replacement',
      'The simplest attack in the paper. On its FIRST encryption only, the subverted code sets the IV to the user\'s key enciphered under the subversion key: one block-cipher call, and the key is in the ciphertext, in plain sight, indistinguishable from random to anyone without K~.',
      para(
        'It does this once and only once, because a repeated IV would show up in the user\'s own checks. That is also why this version needs state — the paper calls it the stateful attack (section 4.1), and ',
        code('IV ← E(K~, K)'),
        ' is the whole of it.',
      ),
    ),
    bias: panelIntro(
      'Biased ciphertexts',
      'The general attack (paper section 4.2), which needs to know almost nothing about the scheme it is subverting. The subverted code keeps a counter j. For the j-th message it keeps drawing fresh randomness until the ciphertext it produces happens to satisfy a one-bit keyed function F — and it arranges for that bit to be bit j of the user\'s key.',
      'Each ciphertext is a perfectly ordinary ciphertext with a perfectly ordinary random IV. It just happens to be one of the roughly half that say the right thing. After 128 of them the whole key has gone out, and the user\'s messages never mattered.',
    ),
  }[mode];

  const controls = h(
    'div',
    { class: 'controls' },
    keyControl.wrap,
    subKeyControl.wrap,
    holderKeyControl.wrap,
    h(
      'div',
      { class: 'control' },
      h('span', { class: 'control-label' }, 'Which encryptor is installed'),
      switchBtn,
      statusLine,
    ),
    emitBox,
    h(
      'div',
      { class: 'control' },
      h('label', { for: p('msg') }, 'Message'),
      msgInput,
      h(
        'div',
        { class: 'input-row' },
        button('Encrypt', async () => {
          await addMessage(msgInput.value);
          renderAll();
        }, { kind: 'primary', id: p('encrypt') }),
        mode === 'bias'
          ? button('Encrypt 128 messages', async () => {
              // From a clean slate, so the counter walks bits 0..127 exactly
              // once and the result is the same whatever came before.
              reset();
              await addMany(128);
            }, { id: p('encrypt-128') })
          : button('Encrypt 8 more', async () => addMany(8), { id: p('encrypt-8') }),
        button('Clear', () => reset(), { id: p('clear') }),
      ),
    ),
  );

  const userSide = h(
    'section',
    { class: 'side side-user', 'aria-labelledby': p('user-heading') },
    h('span', { class: 'side-kicker' }, 'LEFT PANEL'),
    h('h3', { id: p('user-heading') }, 'What the user sees'),
    h('p', { class: 'holder-note' }, 'Their own key, their own messages, the ciphertexts, and the checks they can run.'),
    countLine,
    checksBox,
    histBox,
    logBox,
  );

  const holderSide = h(
    'section',
    { class: 'side side-holder', 'aria-labelledby': p('holder-heading') },
    h('span', { class: 'side-kicker' }, 'RIGHT PANEL — A DIFFERENT PARTY'),
    h('h3', { id: p('holder-heading') }, 'What the holder of the subversion key sees'),
    h('p', { class: 'holder-note' }, 'The same ciphertexts, which it may read off the wire, and K~. It is never given the user\'s key: the code behind this panel takes ciphertexts and K~ and nothing else.'),
    holderBox,
  );

  root.append(
    intro,
    controls,
    h('div', { class: 'split' }, userSide, holderSide),
  );

  if (mode === 'bias') {
    root.append(
      h('h3', {}, 'Watch one ciphertext being chosen'),
      para(
        'This is the whole mechanism, one draw at a time, with the real cipher and the real F. Nothing is simulated: each candidate below is a genuine ciphertext of the message, and the one that is kept is the one the user would have received.',
      ),
      stepperBox,
      negativeBox,
    );
  }

  const tail: HTMLElement[] = [];
  if (mode === 'swap') {
    tail.push(
      learnerCheck(
        'With the subverted encryptor installed, the user runs every check in the left panel and all of them pass. What has the user learned?',
        [
          { label: 'That the encryptor is honest', correct: false },
          { label: 'That the encryptor decrypts correctly — and nothing about where its IVs come from', correct: true },
          { label: 'That the key is safe as long as the IVs stay unique', correct: false },
        ],
        'Passing those checks means the ciphertexts decrypt and the IVs are unremarkable. Neither is evidence about how the IVs were chosen, and the paper proves it: if F is a PRF, the subverted ciphertexts are statistically indistinguishable from real ones even to a test that knows the user\'s key. Detection would have to come from reading the code, not from watching the output.',
      ),
      disclosure(
        'What the paper actually proves here',
        'Theorem 1 bounds a user-side test\'s detection advantage against IV replacement by q²/2ⁿ plus the block cipher\'s PRP advantage; Theorem 3 bounds it against biased ciphertexts by q/2^d plus F\'s PRF advantage, where d is the number of coins the scheme draws. With the 128 bits of IV a counter-mode scheme uses, both bounds are negligible.',
        'The checks on this page are an illustration of that result, not an instance of it. Three statistical tests passing is not a proof, and no amount of testing the output is.',
      ),
    );
  }
  if (mode === 'iv') {
    tail.push(
      learnerCheck(
        'Why does the subverted code replace the IV only once, rather than on every message?',
        [
          { label: 'Because one ciphertext is all the key fits in', correct: false },
          { label: 'Because E(K~, K) is the same bytes every time, so doing it twice would show a repeated IV', correct: true },
          { label: 'Because the second message uses a different key', correct: false },
        ],
        'E(K~, K) is deterministic: the same key under the same subversion key gives the same 16 bytes. Sending it twice would put a repeated IV on the wire, which is exactly what the user\'s second check looks for — and a repeated IV in counter mode is a real break on its own. One ciphertext is enough, so the code only takes that risk once. The paper notes the consequence: a system reset re-runs the first encryption, and the repeat becomes visible.',
      ),
      disclosure(
        'Try it: make it leak every time',
        'Set the first ciphertext aside and press "Encrypt 8 more" after clearing. Then imagine the subverted code dropping its counter — the state it keeps — and re-leaking on each message. The IVs would all be identical, the second check in the left panel would turn red, and so would any ordinary traffic analysis. The lab\'s mutation tests do exactly this to the source and confirm the check catches it.',
      ),
    );
  }
  if (mode === 'bias') {
    tail.push(
      learnerCheck(
        'The subverted encryptor discards a ciphertext whose F bit is wrong and draws again. How many draws does it take on average?',
        [
          { label: 'About 128, one per key bit', correct: false },
          { label: 'About 2', correct: true },
          { label: 'As many as there are possible IVs', correct: false },
        ],
        'F returns one bit, and on a fresh ciphertext it is as good as a coin flip, so each candidate has a one-in-two chance of saying the right thing. The number of draws is geometric with mean 2. This page counts them for you; over 10,000 subverted ciphertexts the lab\'s own test measures a mean between 1.9 and 2.1, and the longest run it has seen is well under thirty.',
      ),
      disclosure(
        'The control: the same extraction on honest ciphertexts',
        'Throw the switch to the honest encryptor and encrypt 128 messages. The right panel still extracts 128 bits — F always returns something — but they are noise: about half of them happen to match the key, which is what chance gives, and the verdict reads KEY NOT RECOVERED because the bytes are compared with the user\'s key before anything is claimed. That comparison is the difference between a recovery and a coincidence.',
      ),
      note(
        'caveat',
        'The paper\'s F also takes a user index, so that one subverter can run against many users at once. This lab has one user and omits it. The concrete choices here — F as the low bit of the first byte of HMAC-SHA-256(K~, C ‖ j), j as a four-byte big-endian integer counted from zero, key bits taken most significant first — are this lab\'s, not the paper\'s, and are pinned by a fixed test vector whose SHA-256 is in the README.',
      ),
    );
  }

  tail.push(
    note(
      'info',
      'Not goals here: a public-key subversion key (the paper\'s appendix B), the stateless variant from the later work of Bellare, Jaeger and Kane, subversion of signatures or of key generation, and any claim about a real product. The extension seams for the first two are marked in the source.',
    ),
  );
  root.append(...tail);

  renderAll();
  if (mode === 'bias') renderStepper();
  void (async () => {
    await addMessage(msgInput.value);
    renderAll();
  })();
}
