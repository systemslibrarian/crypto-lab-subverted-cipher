/**
 * The two pictures this lab draws, both of real values and neither decorative:
 * the IV byte histogram the user-side check judges, and the 128-cell grid in
 * which the holder's recovered key fills in one bit per ciphertext.
 */
import { ivHistogram } from '../subverted/tests.js';
import { h } from './dom.js';

/** 256 bars, one per byte value, scaled to the tallest. The numbers live in the check's text. */
export function histogramFigure(cts: ReadonlyArray<Uint8Array>): HTMLElement {
  const hist = ivHistogram(cts);
  let max = 0;
  for (const c of hist.counts) max = Math.max(max, c);
  const bars = h('div', { class: 'histogram', 'aria-hidden': 'true' });
  for (const c of hist.counts) {
    const pct = max === 0 ? 0 : (100 * c) / max;
    bars.append(h('div', { class: 'histogram-bar', style: `height:${pct.toFixed(1)}%` }));
  }
  const caption = h(
    'p',
    { class: 'histogram-caption' },
    hist.n === 0
      ? 'IV byte histogram: no IV bytes yet. Each bar is one of the 256 byte values.'
      : `IV byte histogram over ${hist.n.toLocaleString('en-US')} bytes: each bar is one of the 256 byte values; a flat row is what uniform randomness looks like.`,
  );
  return h('div', { class: 'histogram-wrap' }, bars, caption);
}

/**
 * The key, bit by bit, as TEXT: '0' / '1' for a leaked bit, '·' for one not yet
 * seen, sixteen to a row with each byte's first bit marked. The grid is
 * aria-hidden because the same information is read out beside it as hex with
 * '?' for unknown nibbles plus a known-bit count; reading 128 single
 * characters aloud would help nobody.
 */
export function bitGrid(bits: ReadonlyArray<0 | 1 | null>): HTMLElement {
  const grid = h('div', { class: 'bitgrid', 'aria-hidden': 'true' });
  bits.forEach((b, j) => {
    grid.append(
      h('span', { class: `bit${b === null ? ' is-unknown' : ''}${j % 8 === 0 ? ' is-byte-start' : ''}` }, b === null ? '·' : String(b)),
    );
  });
  return grid;
}

/** The partially known key as hex, '?' wherever a nibble is not fully known. */
export function partialKeyHex(bits: ReadonlyArray<0 | 1 | null>): string {
  let out = '';
  for (let n = 0; n < bits.length / 4; n++) {
    const quad = bits.slice(4 * n, 4 * n + 4);
    if (quad.some((b) => b === null)) {
      out += '?';
    } else {
      out += ((quad[0]! << 3) | (quad[1]! << 2) | (quad[2]! << 1) | quad[3]!).toString(16);
    }
  }
  return out;
}
