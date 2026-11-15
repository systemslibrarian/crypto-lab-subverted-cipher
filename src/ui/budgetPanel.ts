/**
 * Exhibit 5 -- how little randomness the attack needs.
 *
 * The subverter's only lever is the coins the scheme draws. With c bits of
 * coins it has 2^c candidate ciphertexts, each satisfying F with probability
 * about one half, so it finds no suitable ciphertext with probability
 * 2^-(2^c). That is the paper's remark that about 7 bits of randomness are
 * enough (2^-128), and it is why variable-length padding -- a few bits of
 * unverifiable choice -- is a channel just as an IV is.
 *
 * Every rate on this page is COUNTED FROM RUNS with the real cipher and the
 * real F, with the number of runs shown beside it (invariant 6). Nothing here
 * is a formula being plotted.
 */
import { randomBytes } from '../subverted/bytes.js';
import { BiasedEncryptor, budgetCoins } from '../subverted/subvert-bias.js';
import { button, clear, code, disclosure, h, learnerCheck, note, panelIntro, para, verdict, fmt } from './dom.js';

interface Row {
  readonly bits: number;
  readonly trials: number;
  readonly failures: number;
  readonly expected: number;
}

const DEFAULT_TRIALS = 2000;

export function renderBudgetPanel(root: HTMLElement): void {
  let rows: Row[] = [];
  let running = false;

  const tableBox = h('div', { id: 'budget-table' });
  const verdictBox = h('div', { id: 'budget-verdict' });
  const progress = h('p', { class: 'progress', id: 'budget-progress', role: 'status', 'aria-live': 'polite' });

  const trialsInput = h('input', {
    type: 'number',
    id: 'budget-trials',
    class: 'mono-input num-input',
    value: String(DEFAULT_TRIALS),
    min: '100',
    max: '20000',
    step: '100',
  }) as HTMLInputElement;

  function renderTable(): void {
    clear(tableBox);
    if (rows.length === 0) {
      tableBox.append(h('p', { class: 'help' }, 'No runs yet. Press the button to measure.'));
      return;
    }
    const body = h('tbody');
    for (const r of rows) {
      const rate = r.failures / r.trials;
      body.append(
        h(
          'tr',
          { 'data-bits': String(r.bits) },
          h('th', { scope: 'row' }, `${r.bits}`),
          h('td', {}, fmt(2 ** r.bits)),
          h('td', { 'data-trials': String(r.trials) }, fmt(r.trials)),
          h('td', { 'data-failures': String(r.failures) }, fmt(r.failures)),
          h('td', { 'data-rate': rate.toFixed(4) }, rate.toFixed(4)),
          h('td', {}, r.expected < 0.0001 ? r.expected.toExponential(2) : r.expected.toFixed(4)),
        ),
      );
    }
    const wrap = h(
      'div',
      { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Measured failure rate by coin budget' },
      h(
        'table',
        { class: 'data-table' },
        h(
          'thead',
          {},
          h(
            'tr',
            {},
            h('th', { scope: 'col' }, 'Coin bits c'),
            h('th', { scope: 'col' }, 'Candidates 2^c'),
            h('th', { scope: 'col' }, 'Runs'),
            h('th', { scope: 'col' }, 'No suitable coin'),
            h('th', { scope: 'col' }, 'Measured rate'),
            h('th', { scope: 'col' }, '2^−(2^c)'),
          ),
        ),
        body,
      ),
    );
    const bars = h('div', { class: 'rate-bars' });
    for (const r of rows) {
      const rate = r.failures / r.trials;
      bars.append(
        h(
          'div',
          { class: 'rate-bar' },
          h('span', {}, `c = ${r.bits}, measured`),
          h('div', { class: 'rate-bar-track', 'aria-hidden': 'true' }, h('div', { class: 'rate-bar-fill', style: `width:${(100 * rate * 4).toFixed(2)}%` })),
        ),
        h(
          'div',
          { class: 'rate-bar' },
          h('span', {}, `c = ${r.bits}, 2^−(2^c)`),
          h('div', { class: 'rate-bar-track', 'aria-hidden': 'true' }, h('div', { class: 'rate-bar-fill is-expected', style: `width:${(100 * r.expected * 4).toFixed(2)}%` })),
        ),
      );
    }
    tableBox.append(
      wrap,
      h('p', { class: 'histogram-caption' }, 'The bars repeat the two rate columns at four times scale, measured above its predicted value for each budget.'),
      bars,
    );
  }

  function renderVerdict(): void {
    clear(verdictBox);
    if (rows.length === 0) {
      verdictBox.append(verdict('neutral', 'NOTHING MEASURED YET', 'budget-rates', 'Each rate below is counted from runs, never computed from the formula.'));
      return;
    }
    // Pass when every measured rate sits within three standard errors of
    // 2^-(2^c) -- counted, with the run count shown.
    const off = rows.filter((r) => {
      const rate = r.failures / r.trials;
      const se = Math.sqrt(Math.max(r.expected * (1 - r.expected), 1 / r.trials) / r.trials);
      return Math.abs(rate - r.expected) > Math.max(3 * se, 0.002);
    });
    const totalTrials = rows.reduce((a, r) => a + r.trials, 0);
    verdictBox.append(
      verdict(
        off.length === 0 ? 'pass' : 'fail',
        off.length === 0
          ? `MEASURED RATES MATCH 2^−(2^c) FOR ALL ${rows.length} BUDGETS`
          : `${off.length} OF ${rows.length} BUDGETS ARE OFF THEIR PREDICTED RATE`,
        'budget-rates',
        `${fmt(totalTrials)} runs in total, with the real cipher and the real F; the count for each budget is in the table.`,
      ),
    );
  }

  async function measure(): Promise<void> {
    if (running) return;
    running = true;
    rows = [];
    const trials = Math.max(100, Math.min(20_000, Number(trialsInput.value) || DEFAULT_TRIALS));
    const key = randomBytes(16);
    const subKey = randomBytes(32);
    for (const bits of [1, 2, 3, 4]) {
      progress.textContent = `Running ${fmt(trials)} encryptions at a ${bits}-bit coin budget…`;
      // Yield so the status line above actually paints between budgets.
      await new Promise((r) => setTimeout(r, 0));
      const sub = new BiasedEncryptor(subKey, undefined, budgetCoins(bits), bits);
      let failures = 0;
      for (let i = 0; i < trials; i++) {
        const r = await sub.encrypt(key, randomBytes(8));
        if (!r.ok) failures++;
      }
      rows = [...rows, { bits, trials, failures, expected: 2 ** -(2 ** bits) }];
      renderTable();
      renderVerdict();
    }
    progress.textContent = `Done: ${fmt(trials)} encryptions at each of four coin budgets.`;
    running = false;
  }

  root.append(
    panelIntro(
      'How little randomness it needs',
      'The attack in exhibit 4 spends randomness: it throws ciphertexts away until one says the right thing. So a natural hope is that a scheme which draws only a little randomness is safe, because the subverter runs out of candidates.',
      para(
        'It is a thin hope. With ',
        code('c'),
        ' bits of coins there are ',
        code('2^c'),
        ' candidate ciphertexts, and each fails to say the right thing with probability about one half, so all of them fail with probability ',
        code('2^−(2^c)'),
        '. That number collapses fast: at 3 bits it is about 1 in 256, and at 7 bits it is 2^−128. Counter mode draws 128 bits.',
      ),
    ),
    h(
      'div',
      { class: 'controls' },
      h(
        'div',
        { class: 'control' },
        h('label', { for: 'budget-trials' }, 'Encryptions per budget'),
        trialsInput,
        h('p', { class: 'help' }, 'Between 100 and 20,000. Every rate on this page is counted from this many real runs.'),
      ),
      h(
        'div',
        { class: 'input-row' },
        button('Measure the failure rate', () => void measure(), { kind: 'primary', id: 'budget-run' }),
      ),
      progress,
    ),
    verdictBox,
    tableBox,
    learnerCheck(
      'A scheme pads its messages to a random length, choosing between 1 and 16 extra bytes. How much of a channel is that?',
      [
        { label: 'None — padding is not the IV', correct: false },
        { label: 'Four bits of choice, which is already enough to leak a key bit nineteen times out of twenty', correct: true },
        { label: 'It depends on the key length', correct: false },
      ],
      'Sixteen choices is four bits, so the subverter has sixteen candidate ciphertexts and fails only when all sixteen say the wrong bit: 2^−16, about one in 65,000. The paper makes this point about SSL 3.0 and TLS 1.0 padding and about SSH, where random padding alone is enough to carry the attack even in modes that never surface an IV.',
    ),
    disclosure(
      'What the measured rate is, and is not',
      'It is the fraction of encryptions where no candidate in the budget satisfied F, counted over the runs shown. It is a property of the subverter, not of the user: a user watching the output sees nothing different, because the failures never become ciphertexts.',
      'It is not a detection rate and not a security level. A failure here means the subverted code could not leak this particular bit this time; the paper\'s analysis simply absorbs those into the error term of the key-recovery attack, which is why the attack still works with a budget of seven bits.',
    ),
    note('caveat', 'A failure in this exhibit is reported as "no suitable coin" and no ciphertext is emitted. The page never shows a ciphertext carrying the wrong bit and calls it a success.'),
  );

  renderTable();
  renderVerdict();
}
