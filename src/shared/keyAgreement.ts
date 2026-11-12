/**
 * The key agreement abstraction.
 *
 * Two features of the remaining scope, the Double Ratchet and the hybrid
 * post-quantum handshake, both act on the same point of the system: the root
 * key from which every subsequent message key descends. Written as patches
 * over existing code they are two rewrites of the same region. Written behind
 * a common interface they are two interchangeable implementations, and the
 * ratchet can consume a root key without knowing, or caring, which agreement
 * produced it.
 *
 * `X25519Agreement` (day 6) performs a simplified X3DH. `HybridAgreement`
 * (day 14) combines the same X25519 exchange with an ML-KEM encapsulation and
 * derives the root key from both, so that the result remains secure as long as
 * at least one of the two underlying problems is hard. Because both satisfy
 * this interface, the same conversation can be run in either mode and the
 * difference measured, which is what turns Objective 4 from an estimate into
 * a measurement.
 *
 * If the abstraction leaks anywhere, it will show up on day 15 when the mode
 * is switched at run time. That day exists partly to detect it.
 */

import type { PrekeyBundle } from './protocol';

/** Length of the root key, in bytes. Fixed by the ratchet, not by the agreement. */
export const ROOT_KEY_BYTES = 32;

/**
 * Which agreement produced a root key.
 *
 * Carried so that day 16 can label measurements and day 15 can negotiate the
 * mode without the ratchet or the transport needing to understand either
 * construction.
 */
export type AgreementMode = 'x25519' | 'hybrid';

/**
 * The initiator's output.
 *
 * `header` is the opaque material the responder needs in order to reach the
 * same root key: ephemeral public keys, the identifier of the one-time prekey
 * consumed, and for the hybrid mode the ML-KEM ciphertext. It travels with the
 * first message and is meaningless to the server.
 */
export interface InitiationResult {
  rootKey: Uint8Array;
  header: Uint8Array;
}

export interface ResponseResult {
  rootKey: Uint8Array;
}

export interface KeyAgreement {
  /** Identifies the construction, for negotiation and for benchmarking. */
  readonly mode: AgreementMode;

  /**
   * Derives a root key as the initiating party, from the recipient's
   * published bundle. Returns the header that lets the recipient derive the
   * same value.
   */
  initiate(peerBundle: PrekeyBundle): Promise<InitiationResult>;

  /** Derives the same root key as the responding party, from the header. */
  respond(header: Uint8Array): Promise<ResponseResult>;
}
