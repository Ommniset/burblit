/**
 * Encrypted sessions.
 *
 * A session is established once per correspondent and then reused. The
 * handshake is deliberately not repeated per message: each run consumes one of
 * the recipient's one-time prekeys, which exist in a finite published batch,
 * so repeating it would exhaust the pool within a short conversation and turn
 * an occasional operation into a constant one.
 *
 * MESSAGE PROTECTION
 *
 * ChaCha20-Poly1305 is an AEAD construction: it encrypts and authenticates in
 * a single pass. The authentication half is not incidental. Without it an
 * adversary could flip bits in the ciphertext and the recipient would decrypt
 * the result without any indication that it had been altered, because a
 * stream cipher will happily produce plausible-looking output from modified
 * input. With it, any modification causes decryption to fail outright.
 *
 * The associated data carries the sender and recipient names. These are
 * authenticated but not encrypted, which is exactly what the relay needs: it
 * must read them to route the message, and it cannot alter them without
 * invalidating the tag. A message captured in transit and replayed towards a
 * different recipient therefore fails to decrypt.
 *
 * DIRECTIONAL KEYS
 *
 * Both parties hold the same root key, so if both encrypted under it with a
 * counter-based nonce they would begin at the same value and reuse nonces
 * immediately. Nonce reuse under ChaCha20-Poly1305 is catastrophic: it leaks
 * the exclusive-or of the two plaintexts and undermines the authenticator.
 * Two keys are therefore derived from the root key, one per direction, and
 * each party counts only its own messages. No nonce is ever used twice under
 * a given key, and the arrangement is the one the Double Ratchet extends with
 * per-message derivation.
 *
 * LIMITATIONS, both addressed by the ratchet
 *
 * A session key is fixed for the lifetime of the session, so compromise of a
 * session reveals every message exchanged within it. Sessions are also held
 * in memory only and are lost when the page is reloaded.
 */

import { toBase64, fromBase64, initSodium, sodium } from './crypto';
import type { Identity } from './identity';
import { X25519Agreement, fetchPeerBundle } from './x25519Agreement';

/** Domain separators. Each must be at least 16 bytes to serve as a BLAKE2b key. */
const INITIATOR_TO_RESPONDER = 'Burblit-message-i2r-v1';
const RESPONDER_TO_INITIATOR = 'Burblit-message-r2i-v1';

const KEY_BYTES = 32;
const NONCE_BYTES = 12;

export type SessionRole = 'initiator' | 'responder';

export interface Session {
  peer: string;
  role: SessionRole;
  sendKey: Uint8Array;
  recvKey: Uint8Array;

  /** Number of messages this party has encrypted under `sendKey`. */
  sendCounter: number;

  /**
   * The handshake header, held by the initiator and attached to every message
   * it sends.
   *
   * Retransmission is redundant once the responder has a session, but it makes
   * the responding side recoverable: because sessions are not persisted, a
   * responder that reloads can re-derive the same root key from the header
   * rather than being unable to read anything further. The cost is a few
   * hundred bytes per message, and the day 9 header supersedes this entirely.
   */
  header: string | null;
}

/**
 * Derives the two directional message keys from the root key.
 *
 * The root key is used as the BLAKE2b key and the direction label as the
 * message, so the two outputs are independent even though they descend from a
 * single secret: knowledge of one reveals nothing about the other.
 */
function deriveDirectionalKeys(rootKey: Uint8Array): {
  initiatorToResponder: Uint8Array;
  responderToInitiator: Uint8Array;
} {
  return {
    initiatorToResponder: sodium.crypto_generichash(
      KEY_BYTES,
      sodium.from_string(INITIATOR_TO_RESPONDER),
      rootKey
    ),
    responderToInitiator: sodium.crypto_generichash(
      KEY_BYTES,
      sodium.from_string(RESPONDER_TO_INITIATOR),
      rootKey
    ),
  };
}

/**
 * Builds a session from an already-derived root key.
 *
 * Separated from the two establishment functions below because those reach
 * the network, while this is pure derivation. The split keeps the key schedule
 * testable without a running server, and makes the asymmetry explicit: the
 * only difference between the two roles is which directional key is used for
 * sending and which for receiving.
 */
export function sessionFromRootKey(
  peer: string,
  role: SessionRole,
  rootKey: Uint8Array,
  header: string | null
): Session {
  const keys = deriveDirectionalKeys(rootKey);
  const initiating = role === 'initiator';

  return {
    peer,
    role,
    sendKey: initiating ? keys.initiatorToResponder : keys.responderToInitiator,
    recvKey: initiating ? keys.responderToInitiator : keys.initiatorToResponder,
    sendCounter: 0,
    header,
  };
}

/**
 * Builds a nonce from the sender's message counter.
 *
 * The counter alone guarantees uniqueness, because each direction has its own
 * key and only one party ever encrypts under it. The nonce is transmitted
 * alongside the ciphertext rather than recomputed by the recipient, so a
 * message that arrives late or not at all cannot desynchronise the two sides.
 */
function nonceFromCounter(counter: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setBigUint64(NONCE_BYTES - 8, BigInt(counter), false);
  return nonce;
}

/**
 * Builds the associated data for a message.
 *
 * The colon is an unambiguous separator because the username pattern admits
 * only letters, digits, hyphen and underscore, so no pair of distinct
 * sender/recipient combinations can produce the same string.
 */
function associatedData(from: string, to: string): Uint8Array {
  return sodium.from_string(`${from}:${to}`);
}

// ---------------------------------------------------------------------------
// Session establishment
// ---------------------------------------------------------------------------

const sessions = new Map<string, Session>();

/** Discards all sessions, for example when the identity changes. */
export function clearSessions(): void {
  sessions.clear();
}

/**
 * Returns the session with a correspondent, establishing one if necessary.
 *
 * Called when this party sends first, so it takes the initiating role.
 */
export async function sessionAsInitiator(identity: Identity, peer: string): Promise<Session> {
  const existing = sessions.get(peer);
  if (existing !== undefined) {
    return existing;
  }

  await initSodium();

  const bundle = await fetchPeerBundle(peer);
  const { rootKey, header } = await new X25519Agreement(identity).initiate(bundle);

  const session = sessionFromRootKey(peer, 'initiator', rootKey, toBase64(header));
  sessions.set(peer, session);
  return session;
}

/**
 * Returns the session implied by a received handshake header, establishing one
 * if necessary.
 *
 * The header is compared against the session already held, so a correspondent
 * that begins a new handshake, for instance after clearing its own state,
 * replaces the session rather than being unable to communicate.
 */
export async function sessionAsResponder(
  identity: Identity,
  peer: string,
  header: string
): Promise<Session> {
  const existing = sessions.get(peer);
  if (existing !== undefined && existing.header === header) {
    return existing;
  }

  await initSodium();

  const { rootKey } = await new X25519Agreement(identity).respond(fromBase64(header));

  const session = sessionFromRootKey(peer, 'responder', rootKey, header);
  sessions.set(peer, session);
  return session;
}

/** Returns an established session, or null when none exists. */
export function existingSession(peer: string): Session | null {
  return sessions.get(peer) ?? null;
}

// ---------------------------------------------------------------------------
// Message protection
// ---------------------------------------------------------------------------

/**
 * Encrypts a message, returning the nonce and ciphertext as a single base64
 * value.
 *
 * The nonce is prepended rather than carried in a separate field so that the
 * relay sees one opaque blob and has no structure to interpret or reorder.
 */
export function encryptMessage(
  session: Session,
  plaintext: string,
  from: string,
  to: string
): string {
  const nonce = nonceFromCounter(session.sendCounter);
  session.sendCounter += 1;

  const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    associatedData(from, to),
    null,
    nonce,
    session.sendKey
  );

  const payload = new Uint8Array(nonce.length + ciphertext.length);
  payload.set(nonce, 0);
  payload.set(ciphertext, nonce.length);
  return toBase64(payload);
}

/**
 * Decrypts a message, throwing if it has been altered in any way.
 *
 * Failure is reported rather than tolerated. A modified ciphertext must not
 * decrypt to anything at all: returning plausible-looking output for a message
 * that failed authentication would defeat the purpose of using an AEAD.
 */
export function decryptMessage(
  session: Session,
  payload: string,
  from: string,
  to: string
): string {
  const raw = fromBase64(payload);
  if (raw.length <= NONCE_BYTES) {
    throw new Error('Message payload is too short to contain a nonce and a tag');
  }

  const nonce = raw.slice(0, NONCE_BYTES);
  const ciphertext = raw.slice(NONCE_BYTES);

  const plaintext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    associatedData(from, to),
    nonce,
    session.recvKey
  );

  return sodium.to_string(plaintext);
}
