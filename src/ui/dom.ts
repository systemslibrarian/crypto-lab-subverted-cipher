/** Tiny, dependency-free DOM helpers shared by the panels. No innerHTML anywhere. */
import { fromHex, hex } from '../subverted/bytes.js';

type Attrs = Record<string, string | number | boolean | EventListener | undefined>;
type Child = Node | string | null | undefined;

/** Hyperscript: h('button', { class: 'x', onclick: fn }, 'label'). */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      node.className = String(value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const c of children) {
    if (c == null) continue;
    node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  node.replaceChildren();
}

/** A labelled read-only value shown as wrapping monospace (no scroll region needed). */
export function field(
  label: string,
  value: string | HTMLElement,
  opts: { mono?: boolean; sub?: string; id?: string } = {},
): HTMLElement {
  return h(
    'div',
    { class: 'field' },
    h('span', { class: 'field-label' }, label, opts.sub ? h('span', { class: 'field-sub' }, ` ${opts.sub}`) : null),
    h('code', { class: opts.mono === false ? 'field-value plain' : 'field-value', id: opts.id }, value),
  );
}

export type VerdictState = 'pass' | 'fail' | 'alarm' | 'neutral';

/**
 * A verdict: icon + text + colour, never colour alone. `marker` becomes the
 * `data-verdict` attribute the claims suite and the mutation ledger address;
 * `data-state` carries the state the same way so a test asserts state and
 * text together, not a class name.
 */
export function verdict(state: VerdictState, text: string, marker?: string, summary?: string): HTMLElement {
  const icon = state === 'pass' ? '✓' : state === 'alarm' ? '⚠' : state === 'fail' ? '✕' : '·';
  return h(
    'div',
    { class: `verdict verdict-${state}`, role: 'status', 'data-verdict': marker, 'data-state': state },
    h('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, icon),
    summary
      ? h('span', { class: 'verdict-stack' }, h('span', {}, text), h('span', { class: 'check-summary' }, summary))
      : h('span', {}, text),
  );
}

/** Section heading + intro paragraph(s) for a panel. */
export function panelIntro(title: string, ...paras: (string | HTMLElement)[]): HTMLElement {
  return h(
    'div',
    { class: 'panel-intro' },
    h('h2', {}, title),
    ...paras.map((p) => (typeof p === 'string' ? h('p', {}, p) : p)),
  );
}

/** A paragraph with inline <code> pieces: text('a ', code('b'), ' c'). */
export function para(...children: Child[]): HTMLElement {
  return h('p', {}, ...children);
}
export const code = (s: string): HTMLElement => h('code', {}, s);

/** A "not production" / scoping note. */
export function note(kind: 'info' | 'danger' | 'caveat', ...children: Child[]): HTMLElement {
  return h('p', { class: `callout callout-${kind}` }, ...children);
}

/** Evidence that no longer belongs to the controls currently on screen. */
export function evidenceRetired(text: string): HTMLElement {
  return h(
    'p',
    { class: 'callout callout-caveat evidence-retired', role: 'status', 'aria-live': 'polite' },
    text,
  );
}

/** A shut-by-default disclosure with a heading and body paragraphs or elements. */
export function disclosure(summary: string, ...body: (string | HTMLElement)[]): HTMLElement {
  return h(
    'details',
    { class: 'disclosure' },
    h('summary', {}, summary),
    h('div', { class: 'disclosure-body' }, ...body.map((b) => (typeof b === 'string' ? h('p', {}, b) : b))),
  );
}

export function button(
  label: string,
  onclick: () => void,
  opts: { kind?: 'primary' | 'ghost' | 'danger'; id?: string; ariaLabel?: string } = {},
): HTMLButtonElement {
  return h(
    'button',
    { type: 'button', class: `btn btn-${opts.kind ?? 'ghost'}`, id: opts.id, 'aria-label': opts.ariaLabel, onclick },
    label,
  ) as HTMLButtonElement;
}

/**
 * A hex input for a fixed number of bytes. Validates on every keystroke,
 * marks `aria-invalid`, and calls `onCommit` ONLY with a well-formed value.
 * The caller decides what a commit means (the no-op guard lives there).
 */
export function hexInput(opts: {
  id: string;
  label: string;
  bytes: number;
  value: Uint8Array;
  help?: string;
  onCommit: (bytes: Uint8Array) => void;
}): { wrap: HTMLElement; input: HTMLInputElement; set: (bytes: Uint8Array) => void } {
  const status = h('p', { class: 'help', id: `${opts.id}-status`, role: 'status', 'aria-live': 'polite' }, opts.help ?? '');
  const input = h('input', {
    type: 'text',
    id: opts.id,
    class: 'mono-input',
    value: hex(opts.value),
    spellcheck: 'false',
    autocomplete: 'off',
    'aria-describedby': `${opts.id}-status`,
    'aria-invalid': 'false',
    maxlength: opts.bytes * 2,
  }) as HTMLInputElement;
  const validate = (): void => {
    const v = input.value.trim().toLowerCase();
    let bytes: Uint8Array | null = null;
    try {
      bytes = fromHex(v);
    } catch {
      bytes = null;
    }
    if (bytes && bytes.length === opts.bytes) {
      input.setAttribute('aria-invalid', 'false');
      status.textContent = opts.help ?? '';
      opts.onCommit(bytes);
    } else {
      input.setAttribute('aria-invalid', 'true');
      status.textContent = `Needs exactly ${opts.bytes * 2} hex characters (${opts.bytes} bytes); has ${v.length}${bytes === null && v.length ? ', and not all are hex' : ''}.`;
    }
  };
  input.addEventListener('input', validate);
  const wrap = h('div', { class: 'control' }, h('label', { for: opts.id }, opts.label), input, status);
  return {
    wrap,
    input,
    set(bytes) {
      input.value = hex(bytes);
      validate();
    },
  };
}

/** Hex with the IV part marked, for a CTR$ ciphertext: IV || body. */
export function ciphertextHex(ct: Uint8Array, opts: { leak?: boolean } = {}): HTMLElement {
  return h(
    'code',
    { class: 'hex' },
    h('span', { class: `hex-iv${opts.leak ? ' is-leak' : ''}` }, hex(ct.subarray(0, 16))),
    h('span', { class: 'hex-body' }, hex(ct.subarray(16))),
  );
}

/**
 * A lightweight "predict before you reveal" check: one misconception, a couple
 * of choices, an immediate explanation. The lab stays fully usable whether or
 * not it is answered.
 */
export function learnerCheck(
  question: string,
  options: { label: string; correct: boolean }[],
  explanation: string,
): HTMLElement {
  const feedback = h('div', { class: 'check-feedback', role: 'status', 'aria-live': 'polite' });
  const buttons = options.map((o) =>
    h(
      'button',
      {
        type: 'button',
        class: 'btn btn-ghost check-opt',
        onclick: () => {
          clear(feedback);
          feedback.append(
            h(
              'span',
              { class: `pill pill-${o.correct ? 'ok' : 'bad'}` },
              h('span', { 'aria-hidden': 'true' }, o.correct ? '✓ ' : '✕ '),
              o.correct ? 'Correct' : 'Not quite',
            ),
            h('p', { class: 'check-explain' }, explanation),
          );
        },
      },
      o.label,
    ),
  );
  return h(
    'details',
    { class: 'learner-check' },
    h('summary', {}, 'Quick check'),
    h(
      'div',
      { class: 'check-body' },
      h('p', { class: 'check-q' }, question),
      h('div', { class: 'input-row', role: 'group', 'aria-label': question }, ...buttons),
      feedback,
    ),
  );
}

export const fmt = (n: number): string => n.toLocaleString('en-US');
