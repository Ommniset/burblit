/**
 * The Double Ratchet key schedule (Perrin and Marlinspike, 2016).
 *
 * This module contains only the two key derivation functions the ratchet is
 * built from. Both are pure: they take key material and return key material,
 * hold no state, and reach nothing outside themselves. The state machine that
 * drives them belongs to the sending and receiving logic and is introduced
 * separately.
 *
 * WHY TWO CHAINS
 *
 * A session key that is fixed for the lifetime of a conversation, as used up
 * to this point, means that compromise of that key exposes every message in
 * the conversation, past and future. The ratchet removes both halves of that
 * exposure, using a different mechanism for each.
 *
 * The symmetric chain gives forward secrecy per message. Each message
 * consumes a message key derived from the current chain key, and the chain
 * key is then replaced by its own successor. Because the derivation is
 * one-way, an adversary who seizes the chain key as it stands can derive
 * every future message key but cannot run the chain backwards to recover a
 * single earlier one. Deleting each message key after use is therefore not
 * housekeeping: it is the property itself.
 *
 * The root chain gives break-in recovery, and is advanced by mixing in a
 * fresh Diffie-Hellman output rather than by hashing alone. Hashing alone
 * cannot recover from compromise, since an adversary holding the current
 * state can compute every subsequent state. Introducing new entropy that the
 * adversary did not observe restores secrecy for messages sent afterwards.
 * The Diffie-Hellman ratchet that supplies that entropy is built on top of
 * this function.
 *
 * CONSTRUCTION
 *
 * The specification prescribes HMAC-SHA256. libsodium does not expose it
 * (`crypto_auth` is HMAC-SHA512-256), so keyed BLAKE2b is used, consistently
 * with the handshake. BLAKE2b is a secure pseudo-random function and the
 * construction preserves what the ratchet requires: outputs indistinguishable
 * from random without the key, and no way to invert them. As with the
 * handshake, the consequence is that this implementation is not wire
 * compatible with Signal.
 *
 * Each derivation uses the current key as the BLAKE2b key and a distinct
 * constant label as the message. Two outputs drawn from the same key are
 * therefore independent: recovering a message key reveals nothing about the
 * chain key that follows it, which would otherwise collapse the whole chain.
 *
 * `initSodium()` must have resolved before any function here is called.
 */

import { sodium } from './crypto';

/** Chain keys, root keys and message keys are all 32 bytes. */
export const KEY_BYTES = 32;

/**
 * Domain separators.
 *
 * Signal distinguishes the two chain outputs with single constant bytes. Full
 * labels are used here instead: they cost nothing, they cannot collide with
 * the labels used by the handshake or the message keys, and they make the
 * derivation self-describing when the code is read.
 *
 * Each must be at least crypto_generichash_KEYBYTES_MIN (16) bytes, since the
 * same strings are used as BLAKE2b keys in the root derivation.
 */
const MESSAGE_KEY_LABEL = 'Burblit-ratchet-message-key-v1';
const NEXT_CHAIN_KEY_LABEL = 'Burblit-ratchet-chain-next-v1';
const ROOT_KEY_LABEL = 'Burblit-ratchet-root-next-v1';
const ROOT_CHAIN_LABEL = 'Burblit-ratchet-root-chain-v1';

export interface ChainStep {
  /** Replaces the chain key that produced it. The old value must be discarded. */
  nextChainKey: Uint8Array;

  /** Encrypts exactly one message, and is deleted immediately afterwards. */
  messageKey: Uint8Array;
}

export interface RootStep {
  /** Replaces the root key that produced it. */
  nextRootKey: Uint8Array;

  /** Seeds a fresh symmetric chain for the new Diffie-Hellman ratchet step. */
  chainKey: Uint8Array;
}

/**
 * Advances a symmetric chain by one step.
 *
 * Returns the message key for the current position and the chain key for the
 * next. The caller is responsible for discarding the chain key passed in:
 * retaining it would let anyone who later obtained it rederive every message
 * key from that point onwards, which is precisely what advancing the chain is
 * meant to prevent.
 */
export function advanceChain(chainKey: Uint8Array): ChainStep {
  return {
    messageKey: sodium.crypto_generichash(
      KEY_BYTES,
      sodium.from_string(MESSAGE_KEY_LABEL),
      chainKey
    ),
    nextChainKey: sodium.crypto_generichash(
      KEY_BYTES,
      sodium.from_string(NEXT_CHAIN_KEY_LABEL),
      chainKey
    ),
  };
}

/**
 * Advances the root chain by one Diffie-Hellman ratchet step.
 *
 * The new entropy is the Diffie-Hellman output; the current root key provides
 * continuity with everything that came before. Both are required. Without the
 * Diffie-Hellman output the chain could be run forward by anyone holding the
 * current state, so break-in recovery would be lost; without the root key the
 * chain would have no history and a single compromised exchange would be
 * enough to reconstruct it.
 *
 * The root key is supplied as the BLAKE2b key and the Diffie-Hellman output as
 * part of the message, so neither can be varied independently to steer the
 * result.
 */
export function advanceRoot(rootKey: Uint8Array, dhOutput: Uint8Array): RootStep {
  const nextRootKey = sodium.crypto_generichash(
    KEY_BYTES,
    concat(sodium.from_string(ROOT_KEY_LABEL), dhOutput),
    rootKey
  );

  const chainKey = sodium.crypto_generichash(
    KEY_BYTES,
    concat(sodium.from_string(ROOT_CHAIN_LABEL), dhOutput),
    rootKey
  );

  return { nextRootKey, chainKey };
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(left.length + right.length);
  combined.set(left, 0);
  combined.set(right, left.length);
  return combined;
}

/**
 * Overwrites key material in place.
 *
 * JavaScript offers no guarantee that this prevents the bytes from surviving
 * elsewhere: the engine may have copied the array during garbage collection,
 * and nothing stops the operating system from having paged it out. It is
 * called where a key is discarded because it narrows the window in which a
 * value is readable, and because the absence of any attempt at erasure would
 * be a worse default. The limitation is recorded rather than papered over.
 */
export function wipe(key: Uint8Array): void {
  key.fill(0);
}
