/**
 * Exhibit 1 -- the honest encryptor.
 *
 * Real AES-CTR with a fresh random IV, the ciphertext laid out so the IV is
 * visibly the first 16 bytes, and the three checks a careful user can run.
 * Everything a later exhibit will subvert is established here first, including
 * the known-answer tests: this page recomputes FIPS 197, NIST SP 800-38A,
 * RFC 4231 and the McGrew-Viega GCM vectors in the browser rather than
 * asserting that it passes them somewhere else.
 */
import { concat, equal, hex, randomBytes, utf8 } from '../subverted/bytes.js';
import { decrypt, encrypt, encryptWithIv, ivOf } from '../subverted/ctr.js';
import { encryptBlock, decryptBlock } from '../subverted/block.js';
import { hmacSha256 } from '../subverted/prf.js';
import { gcmEncrypt } from '../subverted/unique.js';
import { verifiedRecord } from '../subverted/display-gate.js';
import { runUserChecks } from '../subverted/tests.js';
import { FIPS197_C1, GCM_VECTORS, NIST_F51, RFC4231 } from '../subverted/vectors.js';
import type { Record } from '../subverted/types.js';
import {
  button,
  ciphertextHex,
  clear,
  code,
  disclosure,
  field,
  h,
  hexInput,
  learnerCheck,
  note,
  panelIntro,
  para,
  verdict,
} from './dom.js';
import { histogramFigure } from './viz.js';

const DEFAULT_MESSAGE = 'Meet me where the river bends, at nine.';

export function renderHonestPanel(root: HTMLElement): void {
  let key = randomBytes(16);
  let records: Record[] = [];

  const log = h('ul', { class: 'log', id: 'honest-log', role: 'list' });
  const checksBox = h('div', { class: 'checks', id: 'honest-checks' });
  const histBox = h('div', { id: 'honest-histogram' });
  const roundTripBox = h('div', { id: 'honest-roundtrip' });

  const keyControl = hexInput({
    id: 'honest-key',
    label: 'Your AES-128 key (hex, 16 bytes)',
    bytes: 16,
    value: key,
    help: 'Session only. Nothing here is stored or sent anywhere.',
    onCommit: (bytes) => {
      if (equal(bytes, key)) return; // no-op guard: re-entering the same key retires nothing
      key = bytes;
      records = [];
      renderAll();
    },
  });

  const msgInput = h('textarea', {
    id: 'honest-msg',
    class: 'msg-input',
    rows: 2,
    'aria-label': 'Message to encrypt',
  }) as HTMLTextAreaElement;
  msgInput.value = DEFAULT_MESSAGE;

  function addMessage(text: string): void {
    const msg = utf8(text);
    // Invariant 1: honest decryption is checked BEFORE anything is displayed.
    records = [...records, verifiedRecord(key, msg, encrypt(key, msg))];
    renderAll();
  }

  function renderLog(): void {
    clear(log);
    const shown = records.slice(-8);
    if (shown.length === 0) {
      // An empty `role="list"` has no `listitem` children, which is an
      // aria-required-children failure -- and an empty region is also the
      // thing a scan happily calls accessible. Say what the state is instead.
      log.append(h('li', { class: 'log-row log-empty', role: 'listitem' }, 'No ciphertexts yet. Press Encrypt.'));
      return;
    }
    shown.forEach((r, i) => {
      const n = records.length - shown.length + i;
      log.append(
        h(
          'li',
          { class: 'log-row', role: 'listitem' },
          h('span', { class: 'log-idx' }, `#${n}`),
          h(
            'span',
            { class: `log-msg${r.msg.length === 0 ? ' log-msg-empty' : ''}` },
            r.msg.length === 0 ? '(empty message)' : new TextDecoder().decode(r.msg),
          ),
          h('span', { class: 'log-meta' }, `IV (first 16 bytes) then body, ${r.ct.length} bytes:`),
          ciphertextHex(r.ct),
        ),
      );
    });
    if (records.length > shown.length) {
      log.append(h('li', { class: 'log-more', role: 'listitem' }, `${records.length - shown.length} earlier ciphertexts not shown.`));
    }
  }

  function renderChecks(): void {
    clear(checksBox);
    const checks = runUserChecks(key, records);
    for (const c of checks) {
      checksBox.append(
        h(
          'div',
          { class: 'check-row' },
          verdict(
            c.state === 'pass' ? 'pass' : c.state === 'fail' ? 'fail' : 'neutral',
            `${c.label}: ${c.state === 'pass' ? 'PASSES' : c.state === 'fail' ? 'FAILS' : 'not yet conclusive'}`,
            `honest-${c.id}`,
            c.summary,
          ),
        ),
      );
    }
    clear(histBox);
    histBox.append(histogramFigure(records.map((r) => r.ct)));
  }

  function renderRoundTrip(): void {
    clear(roundTripBox);
    const last = records[records.length - 1];
    if (!last) {
      roundTripBox.append(verdict('neutral', 'Nothing encrypted yet.', 'honest-last'));
      return;
    }
    const back = decrypt(key, last.ct);
    const ok = back !== null && equal(back, last.msg);
    roundTripBox.append(
      field('Latest ciphertext', ciphertextHex(last.ct), { sub: `${last.ct.length} bytes = 16-byte IV + ${last.ct.length - 16} body` }),
      field('IV alone', hex(ivOf(last.ct))),
      field('Decrypted with your key', back === null ? '(too short to decrypt)' : new TextDecoder().decode(back) || '(empty message)', { mono: false }),
      verdict(
        ok ? 'pass' : 'fail',
        ok ? 'DECRYPTS TO THE MESSAGE YOU TYPED' : 'DOES NOT DECRYPT TO THE MESSAGE YOU TYPED',
        'honest-last',
        ok ? 'Compared byte for byte against the plaintext, under the key above.' : 'The bytes differ.',
      ),
    );
  }

  function renderAll(): void {
    renderLog();
    renderChecks();
    renderRoundTrip();
  }

  const katList = h('ul', { class: 'kat-list', id: 'honest-kats', role: 'list' });
  const katVerdict = h('div', { id: 'honest-kat-verdict' });

  async function runKats(): Promise<void> {
    type Kat = { name: string; got: string; want: string };
    const results: Kat[] = [];
    results.push({
      name: 'AES-128, FIPS 197 Appendix C.1 (encrypt one block)',
      got: hex(encryptBlock(FIPS197_C1.key, FIPS197_C1.plaintext)),
      want: hex(FIPS197_C1.ciphertext),
    });
    results.push({
      name: 'AES-128, FIPS 197 Appendix C.1 (decrypt the same block)',
      got: hex(decryptBlock(FIPS197_C1.key, FIPS197_C1.ciphertext)),
      want: hex(FIPS197_C1.plaintext),
    });
    results.push({
      name: 'AES-128-CTR, NIST SP 800-38A F.5.1 (four blocks, the counter carries)',
      got: hex(encryptWithIv(NIST_F51.key, NIST_F51.counter, NIST_F51.plaintext).subarray(16)),
      want: hex(NIST_F51.ciphertext),
    });
    const rfc = RFC4231[1]!;
    results.push({
      name: `HMAC-SHA-256, RFC 4231 ${rfc.name}`,
      got: hex(await hmacSha256(rfc.key, rfc.data)),
      want: hex(rfc.tag),
    });
    const gcm = GCM_VECTORS[1]!;
    results.push({
      name: `AES-128-GCM, McGrew-Viega ${gcm.name}`,
      got: hex(await gcmEncrypt(gcm.key, gcm.iv, gcm.aad, gcm.plaintext)),
      want: hex(concat(gcm.ciphertext, gcm.tag)),
    });

    clear(katList);
    let passed = 0;
    for (const r of results) {
      const ok = r.got === r.want;
      if (ok) passed++;
      katList.append(
        h(
          'li',
          { class: `kat-row${ok ? '' : ' is-bad'}`, role: 'listitem' },
          h('span', { class: 'kat-name' }, r.name),
          h('span', { class: 'log-meta' }, ok ? 'computed here, equal to the document:' : 'computed here, DIFFERS from the document:'),
          h('code', { class: 'hex' }, r.got),
        ),
      );
    }
    clear(katVerdict);
    katVerdict.append(
      verdict(
        passed === results.length ? 'pass' : 'fail',
        passed === results.length
          ? `${passed} OF ${results.length} STANDARD VECTORS REPRODUCED IN THIS BROWSER`
          : `${results.length - passed} OF ${results.length} STANDARD VECTORS DO NOT MATCH`,
        'honest-kats',
        'Recomputed on load, compared byte for byte with the published value.',
      ),
    );
  }

  root.append(
    panelIntro(
      'The honest encryptor',
      'Encryption turns a message into bytes only someone with the key can read. The scheme here is AES in counter mode with a random starting point, which is what most encrypted traffic looks like underneath: pick 16 random bytes, call them the IV, send them in front of the ciphertext so the receiver can decrypt.',
      para(
        'The IV has to be unpredictable, and it is sent in the clear, so a reader can see it and a reader can check it. That is the part worth holding on to: ',
        code('ciphertext = IV ‖ AES-CTR_K(message)'),
        '. Everything in the next five exhibits happens inside those first 16 bytes.',
      ),
    ),
    h(
      'div',
      { class: 'controls' },
      keyControl.wrap,
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'honest-msg' }, 'Message'),
        msgInput,
        h(
          'div',
          { class: 'input-row' },
          button('Encrypt', () => addMessage(msgInput.value), { kind: 'primary', id: 'honest-encrypt' }),
          button('Encrypt 40 random messages', () => {
            for (let i = 0; i < 40; i++) addMessage(`sample message ${records.length}`);
          }, { id: 'honest-encrypt-40' }),
          button('Encrypt an empty message', () => addMessage(''), { id: 'honest-encrypt-empty' }),
          button('Clear', () => {
            records = [];
            renderAll();
          }, { id: 'honest-clear' }),
        ),
      ),
    ),
    h('div', { class: 'output' }, roundTripBox),
    h('h3', {}, 'The checks you can run with your own key'),
    para(
      'These are the tests a careful user can actually perform: decrypt everything and compare, look for a repeated IV, and look at the distribution of the IV bytes. Remember what they pass on, because every one of them will still pass in exhibits 3 and 4.',
    ),
    checksBox,
    histBox,
    h('h3', {}, 'Your ciphertexts'),
    log,
    h('h3', {}, 'The primitives, recomputed here'),
    para('Each of these is computed in your browser on load and compared with the value printed in the standard. The IV accent marks the first 16 bytes of a ciphertext throughout this lab.'),
    katVerdict,
    katList,
    disclosure(
      'Why the IV is in the ciphertext at all',
      'Counter mode turns a block cipher into a stream cipher: encrypt IV, IV+1, IV+2 … and XOR the result into the message. The receiver needs the same starting counter, so it is sent in front, unencrypted. It does not need to be secret. It does need to be fresh, because two messages encrypted from the same starting counter are XORed with the same keystream.',
      'Nothing about counter mode says WHERE those 16 bytes come from, only that they should look random. There is no way, from outside, to tell a random IV from one chosen with care. That gap is the subject of this lab.',
    ),
    learnerCheck(
      'The IV is sent in the clear, in front of every ciphertext. What does an eavesdropper learn from it?',
      [
        { label: 'Nothing — it is just 16 random bytes', correct: false },
        { label: 'Nothing, unless whoever chose it meant to say something', correct: true },
        { label: 'Part of the key', correct: false },
      ],
      'From outside, an IV is 16 bytes that look random, and a genuinely random one tells you nothing. But "looks random" is not "was random": whoever wrote the encryptor chose those bytes, and no test run on the output can tell a coin flip from a careful choice that imitates one. The next exhibits put something in them.',
    ),
    note('info', 'Not a goal here: this exhibit does not prove AES or counter mode secure, and the three checks above are not a detector for subverted software. See exhibit 2.'),
  );

  addMessage(DEFAULT_MESSAGE);
  void runKats();
}
