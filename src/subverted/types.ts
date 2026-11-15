/**
 * The interfaces the exhibits share. Two of them are extension seams the brief
 * asks to be shaped now and left unbuilt:
 *
 *  - `BaseScheme`  -- so CBC with a random IV (also surfaces its IV, paper
 *                     section 4.1) could sit beside CTR$ and be subverted the
 *                     same way. Not built here.                 // [extension] point
 *  - `Subversion`  -- so the stateless variant from Bellare, Jaeger and Kane
 *                     (ACM CCS 2015, cited by the paper as subsequent work) or a
 *                     padding-based channel (paper appendix A) could be added
 *                     beside the two attacks built here. Not built here.
 *                                                                // [extension] point
 */

/**
 * A symmetric encryption scheme as the biased-ciphertext subverter sees it:
 * something that consumes `coinBytes` of randomness per message, which the
 * subverter may choose. `coinBytes === 0` means there is nothing to choose,
 * which is the whole point of exhibit 6.
 */
export interface BaseScheme {
  readonly name: string;
  readonly coinBytes: number;
  encrypt(key: Uint8Array, msg: Uint8Array, coins?: Uint8Array): Promise<Uint8Array>;
}

/**
 * Where a subverted encryptor's candidate coins come from. In normal use they
 * are fresh platform randomness; the fixed test vector (brief check D) and
 * exhibit 5's coin budget inject one. `t` is the candidate index for the j-th
 * ciphertext, counted from 0.
 */
export interface CoinSource {
  next(j: number, t: number): Uint8Array | Promise<Uint8Array>;
}

/** A subverted encryptor: same inputs as the honest one, plus hidden state. */
export interface Subversion<Result> {
  readonly name: string;
  encrypt(userKey: Uint8Array, msg: Uint8Array): Promise<Result>;
  reset(): void;
}

/** One message/ciphertext pair as the user's side records it. */
export interface Record {
  readonly msg: Uint8Array;
  readonly ct: Uint8Array;
}
