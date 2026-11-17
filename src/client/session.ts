/**
 * Encrypted sessions, driven by the Double Ratchet.
 *
 * TWO RATCHETS, TWO PROPERTIES
 *
 * The symmetric ratchet advances a chain by hashing, producing one key per
 * message and discarding it afterwards. That gives forward secrecy: an
 * adversary holding the chain as it stands cannot run it backwards to recover
 * a message already sent. What it cannot give is recovery from compromise,
 * because hashing is deterministic and an adversary holding the current state
 * can compute every state that follows it, indefinitely.
 *
 * The Diffie-Hellman ratchet supplies what hashing cannot: entropy the
 * adversary did not observe. Each party holds a ratchet keypair and advertises
 * its public half on every message. When a party observes that its
 * correspondent's ratchet key has changed, it performs a ratchet step,
 * deriving a fresh receiving chain from its own private key and the new public
 * key, then generating a new keypair and deriving a fresh sending chain.
 *
 * MODE NEGOTIATION
 *
 * The root key that seeds all of this comes from one of two agreements, and
 * the ratchet cannot tell which: both satisfy the same interface and both
 * yield 32 bytes. The initiator chooses, guided by a policy and by what the
 * correspondent has published; the responder is told, by the mode named in
 * the handshake header.
 *
 * The policy exists for two reasons. The first is measurement: the same
 * conversation can be run under either agreement and the difference observed,
 * which is what makes the comparison empirical rather than estimated. The
 * second is the downgrade problem. An active relay can strip the post-quantum
 * key from a bundle it serves, and no signature prevents that, because a
 * signature protects what a bundle contains and not what it omits. A client
 * that requires the hybrid agreement therefore fails rather than proceeding,
 * which converts a silent degradation into a visible error. That is the only
 * defence available without an authenticated binding between names and keys,
 * and it is recorded as such in the threat model.
 *
 * OUT-OF-ORDER DELIVERY
 *
 * A chain can only be advanced forwards, so keys for positions skipped over
 * are retained rather than discarded, indexed by the ratchet key and message
 * number that identify them, and consumed when the message they belong to
 * arrives. The same applies across a ratchet step: the header states how long
 * the superseded sending chain was, so the remainder of the corresponding
 * receiving chain is derived and stored before the step is taken.
 *
 * The store is bounded, because an adversary could otherwise force unbounded
 * allocation by sending messages with ever-increasing numbers. When full it
 * evicts the oldest entry: a message missing for a long time is the one least
 * likely still to arrive, and degrading is better than refusing to serve.
 *
 * LIMITATIONS
 *
 * Retained keys weaken forward secrecy for exactly the messages they belong
 * to, which is the unavoidable cost of tolerating loss and is bounded by the
 * size of the store. Sessions are held in memory and lost on reload.
 */

import type { AgreementMode, KeyAgreement } from '../shared/keyAgreement';
import { toBase64, fromBase64, initSodium, sodium } from './crypto';
import { HybridAgreement, supportsHybrid } from './hybridAgreement';
import type { Identity, KeyPair } from './identity';
import { advanceChain, advanceRoot, wipe } from './ratchet';
import { X25519Agreement, fetchPeerBundle } from './x25519Agreement';

const NONCE_BYTES = 12;

/**
 * How far a single message may advance a receiving chain.
 *
 * Without a bound, a message claiming an arbitrarily large number would
 * compel the recipient to perform that many derivations before discovering it
 * could not decrypt the result, which is a denial of service requiring one
 * forged frame.
 */
export const MAX_SKIPPED_MESSAGES = 1000;

/** How many skipped message keys a session retains across all chains. */
export const MAX_STORED_KEYS = 2000;

export type SessionRole = 'initiator' | 'responder';

/**
 * Which agreement a client will use.
 *
 * `auto` takes the hybrid agreement where the correspondent has published the
 * material for it. The two explicit values force the choice: `hybrid` refuses
 * to proceed without post-quantum protection rather than falling back, and
 * `x25519` is what allows a conversation to be run classically for comparison.
 */
export type ModePolicy = 'auto' | 'hybrid' | 'x25519';

let modePolicy: ModePolicy = 'auto';

export function setModePolicy(policy: ModePolicy): void {
  modePolicy = policy;
}

export function getModePolicy(): ModePolicy {
  return modePolicy;
}

export interface Session {
  peer: string;
  role: SessionRole;

  /** Which agreement produced this session's root key. */
  agreementMode: AgreementMode;

  /** The root chain, advanced by every Diffie-Hellman ratchet step. */
  rootKey: Uint8Array;

  /** This party's current ratchet keypair. Replaced at every step. */
  ratchetKeyPair: KeyPair;

  /** The correspondent's current ratchet public key, base64. */
  remoteRatchetKey: string | null;

  /** Null until a sending chain exists, which for a responder means until
   *  the first message has been received. */
  sendingChainKey: Uint8Array | null;

  /** Null until the correspondent's first message establishes it. */
  receivingChainKey: Uint8Array | null;

  /** Position within the current sending chain. */
  sendCounter: number;

  /** Position within the current receiving chain. */
  receiveCounter: number;

  /** Length of the sending chain superseded by the last ratchet step. */
  previousSendingChainLength: number;

  /**
   * Keys for positions the receiving chains have passed without a message
   * arriving, indexed by `ratchetKey:messageNumber`. Insertion order is
   * meaningful: the oldest entry is evicted when the store is full.
   */
  skippedKeys: Map<string, Uint8Array>;

  /**
   * The handshake header, held by the initiator and attached to every message
   * it sends, so that a responder which has lost its session can re-derive
   * the root key rather than being unable to read anything further.
   */
  handshakeHeader: string | null;
}

/** The per-message header, carried alongside the ciphertext. */
export interface MessageHeader {
  v: 1;
  /** Handshake header, present while the initiator keeps resending it. */
  hs?: string;
  /** The sender's current ratchet public key, base64. */
  dh: string;
  /** Length of the sender's previous sending chain. */
  pn: number;
  /** Position of this message within the sender's current sending chain. */
  n: number;
}

export interface OutgoingMessage {
  /** Base64 ciphertext. */
  payload: string;
  /** Base64 of the encoded message header. */
  header: string;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function diffieHellman(ownPrivate: Uint8Array, peerPublic: string): Uint8Array {
  return sodium.crypto_scalarmult(ownPrivate, fromBase64(peerPublic));
}

function encodeHeader(header: MessageHeader): string {
  return toBase64(sodium.from_string(JSON.stringify(header)));
}

/** Narrows an untrusted header. A peer's frame is not trusted to be well formed. */
export function decodeHeader(encoded: string): MessageHeader {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sodium.to_string(fromBase64(encoded)));
  } catch {
    throw new Error('Message header is not valid encoded JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Message header is not an object');
  }

  const candidate = parsed as Record<string, unknown>;

  if (candidate.v !== 1) {
    throw new Error(`Unsupported message header version: ${String(candidate.v)}`);
  }
  if (typeof candidate.dh !== 'string') {
    throw new Error('Message header carries no ratchet key');
  }
  if (typeof candidate.pn !== 'number' || !Number.isInteger(candidate.pn) || candidate.pn < 0) {
    throw new Error('Message header carries an invalid previous chain length');
  }
  if (typeof candidate.n !== 'number' || !Number.isInteger(candidate.n) || candidate.n < 0) {
    throw new Error('Message header carries an invalid message number');
  }
  if (candidate.hs !== undefined && typeof candidate.hs !== 'string') {
    throw new Error('Message header carries an invalid handshake header');
  }

  return {
    v: 1,
    dh: candidate.dh,
    pn: candidate.pn,
    n: candidate.n,
    ...(typeof candidate.hs === 'string' ? { hs: candidate.hs } : {}),
  };
}

/**
 * Extracts the handshake header a message carries, if any.
 *
 * Used before a session exists, to decide whether an incoming message can
 * establish one.
 */
export function handshakeHeaderFrom(encoded: string): string | null {
  try {
    return decodeHeader(encoded).hs ?? null;
  } catch {
    return null;
  }
}

/**
 * Reads the agreement named by a handshake header.
 *
 * Both headers declare their own mode, which is what lets the responder
 * select the matching implementation without having to guess from the
 * structure. An unrecognised value is an error rather than a default: silently
 * treating an unknown mode as classical would be a downgrade performed by the
 * recipient on itself.
 */
export function handshakeMode(encodedHandshakeHeader: string): AgreementMode {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sodium.to_string(fromBase64(encodedHandshakeHeader)));
  } catch {
    throw new Error('Handshake header is not valid encoded JSON');
  }

  const mode = (parsed as Record<string, unknown> | null)?.mode;
  if (mode !== 'x25519' && mode !== 'hybrid') {
    throw new Error(`Handshake header names an unknown agreement: ${String(mode)}`);
  }
  return mode;
}

function nonceFromCounter(counter: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setBigUint64(NONCE_BYTES - 8, BigInt(counter), false);
  return nonce;
}

/**
 * Builds the associated data for a message.
 *
 * The ratchet key, chain length and message number are included because they
 * determine which keys the recipient derives; altering any of them must
 * invalidate the message rather than silently redirect the derivation. The
 * handshake header is excluded: removing it can only prevent a session from
 * being established, and including it would break authentication for messages
 * sent after the initiator stops resending it.
 */
function associatedData(from: string, to: string, header: MessageHeader): Uint8Array {
  return sodium.from_string(`${from}:${to}:${header.dh}:${header.pn}:${header.n}`);
}

function skippedKeyIndex(ratchetKey: string, messageNumber: number): string {
  return `${ratchetKey}:${messageNumber}`;
}

// ---------------------------------------------------------------------------
// Session construction
// ---------------------------------------------------------------------------

/**
 * Builds the initiating party's session.
 *
 * The recipient's signed prekey serves as its first ratchet public key, so a
 * sending ratchet step can be performed at once and the first message
 * encrypted without the recipient ever having been online.
 */
export function initiatorSession(
  peer: string,
  rootKey: Uint8Array,
  peerSignedPrekey: string,
  handshakeHeader: string,
  agreementMode: AgreementMode = 'x25519'
): Session {
  const ratchetKeyPair = sodium.crypto_box_keypair();
  const step = advanceRoot(rootKey, diffieHellman(ratchetKeyPair.privateKey, peerSignedPrekey));

  return {
    peer,
    role: 'initiator',
    agreementMode,
    rootKey: step.nextRootKey,
    ratchetKeyPair,
    remoteRatchetKey: peerSignedPrekey,
    sendingChainKey: step.chainKey,
    receivingChainKey: null,
    sendCounter: 0,
    receiveCounter: 0,
    previousSendingChainLength: 0,
    skippedKeys: new Map(),
    handshakeHeader,
  };
}

/**
 * Builds the responding party's session.
 *
 * It begins with no chains. Its signed prekey pair is its first ratchet
 * keypair, which is the pair the initiator has already performed a
 * Diffie-Hellman against; both chains are derived when the first message
 * arrives and the ratchet step is performed.
 */
export function responderSession(
  peer: string,
  rootKey: Uint8Array,
  signedPrekeyPair: KeyPair,
  agreementMode: AgreementMode = 'x25519'
): Session {
  return {
    peer,
    role: 'responder',
    agreementMode,
    rootKey,
    ratchetKeyPair: signedPrekeyPair,
    remoteRatchetKey: null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendCounter: 0,
    receiveCounter: 0,
    previousSendingChainLength: 0,
    skippedKeys: new Map(),
    handshakeHeader: null,
  };
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

const sessions = new Map<string, Session>();

/** Discards all sessions, for example when the identity or the policy changes. */
export function clearSessions(): void {
  sessions.clear();
}

/** Returns an established session, or null when none exists. */
export function existingSession(peer: string): Session | null {
  return sessions.get(peer) ?? null;
}

/**
 * Decides which agreement an outgoing handshake will use.
 *
 * Kept as a pure function of the policy and what the correspondent has
 * published, so the rule can be checked exhaustively without a network or a
 * registry. The decision is small but consequential: it is the point at which
 * a downgrade would occur if one were permitted.
 *
 * Refusing to fall back when the hybrid agreement is required is the only
 * protection available against a relay that strips post-quantum material from
 * a bundle, because a signature covers what the bundle contains and not what
 * it lacks.
 */
export function chooseMode(
  policy: ModePolicy,
  hybridAvailable: boolean,
  peer: string
): AgreementMode {
  if (policy === 'x25519') {
    return 'x25519';
  }
  if (policy === 'hybrid') {
    if (!hybridAvailable) {
      throw new Error(
        `${peer} has published no post-quantum key, and this client is configured to ` +
          'require the hybrid agreement; refusing to fall back'
      );
    }
    return 'hybrid';
  }
  return hybridAvailable ? 'hybrid' : 'x25519';
}

function agreementFor(identity: Identity, mode: AgreementMode): KeyAgreement {
  return mode === 'hybrid' ? new HybridAgreement(identity) : new X25519Agreement(identity);
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
  const agreement = agreementFor(identity, chooseMode(modePolicy, supportsHybrid(bundle), peer));
  const { rootKey, header } = await agreement.initiate(bundle);

  const session = initiatorSession(
    peer,
    rootKey,
    bundle.signedPrekey,
    toBase64(header),
    agreement.mode
  );
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
  handshakeHeader: string
): Promise<Session> {
  const existing = sessions.get(peer);
  if (existing !== undefined && existing.handshakeHeader === handshakeHeader) {
    return existing;
  }

  await initSodium();

  const mode = handshakeMode(handshakeHeader);

  // A client configured to require post-quantum protection rejects a
  // classical handshake rather than answering it. Otherwise an adversary
  // could downgrade a conversation simply by initiating it.
  if (modePolicy === 'hybrid' && mode !== 'hybrid') {
    throw new Error(
      `${peer} opened a ${mode} session, and this client is configured to require ` +
        'the hybrid agreement; refusing to answer'
    );
  }

  const { rootKey } = await agreementFor(identity, mode).respond(fromBase64(handshakeHeader));

  const session = responderSession(peer, rootKey, identity.signedPrekeyPair, mode);
  session.handshakeHeader = handshakeHeader;
  sessions.set(peer, session);
  return session;
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

export function encryptMessage(
  session: Session,
  plaintext: string,
  from: string,
  to: string
): OutgoingMessage {
  if (session.sendingChainKey === null) {
    // A responder has no sending chain until the first message arrives and
    // the ratchet step derives one.
    throw new Error(`No sending chain established with ${session.peer} yet`);
  }

  const counter = session.sendCounter;
  const { messageKey, nextChainKey } = advanceChain(session.sendingChainKey);

  // The chain key just consumed is overwritten and replaced. Retaining it
  // would let anyone who later obtained it rederive every message key from
  // this point forward, which is what advancing the chain exists to prevent.
  wipe(session.sendingChainKey);
  session.sendingChainKey = nextChainKey;
  session.sendCounter = counter + 1;

  const header: MessageHeader = {
    v: 1,
    dh: toBase64(session.ratchetKeyPair.publicKey),
    pn: session.previousSendingChainLength,
    n: counter,
    ...(session.handshakeHeader !== null ? { hs: session.handshakeHeader } : {}),
  };

  const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    associatedData(from, to, header),
    null,
    nonceFromCounter(counter),
    messageKey
  );

  // The message key encrypts exactly one message and is of no further use.
  wipe(messageKey);

  return { payload: toBase64(ciphertext), header: encodeHeader(header) };
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

function decrypt(
  messageKey: Uint8Array,
  ciphertext: Uint8Array,
  from: string,
  to: string,
  header: MessageHeader
): string {
  const plaintext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    associatedData(from, to, header),
    nonceFromCounter(header.n),
    messageKey
  );
  return sodium.to_string(plaintext);
}

/**
 * Derives and retains the keys for positions a chain is about to pass.
 *
 * Returns the chain key the walk ended on. The caller holds the result aside
 * until the message authenticates, so a forged frame cannot populate the store
 * or move the chain.
 */
function skipTo(
  chainKey: Uint8Array,
  from: number,
  until: number,
  ratchetKey: string,
  into: Map<string, Uint8Array>
): Uint8Array {
  const distance = until - from;
  if (distance > MAX_SKIPPED_MESSAGES) {
    throw new Error(
      `Advancing to message ${until} would skip ${distance} positions, beyond the ` +
        `limit of ${MAX_SKIPPED_MESSAGES}; refusing to advance`
    );
  }

  let current = chainKey;
  for (let position = from; position < until; position += 1) {
    const advanced = advanceChain(current);
    into.set(skippedKeyIndex(ratchetKey, position), advanced.messageKey);
    current = advanced.nextChainKey;
  }
  return current;
}

/**
 * Performs a Diffie-Hellman ratchet step against a new remote key.
 *
 * Two root steps are taken. The first, against this party's existing private
 * key, derives the receiving chain for the messages now arriving. The second,
 * against a freshly generated private key, derives the sending chain for the
 * replies. Generating that key here is what denies an adversary holding the
 * previous state any way to follow the conversation forward.
 */
function ratchetStep(
  rootKey: Uint8Array,
  ownKeyPair: KeyPair,
  remoteRatchetKey: string
): {
  rootKey: Uint8Array;
  ratchetKeyPair: KeyPair;
  receivingChainKey: Uint8Array;
  sendingChainKey: Uint8Array;
} {
  const receiving = advanceRoot(rootKey, diffieHellman(ownKeyPair.privateKey, remoteRatchetKey));

  const ratchetKeyPair = sodium.crypto_box_keypair();
  const sending = advanceRoot(
    receiving.nextRootKey,
    diffieHellman(ratchetKeyPair.privateKey, remoteRatchetKey)
  );

  return {
    rootKey: sending.nextRootKey,
    ratchetKeyPair,
    receivingChainKey: receiving.chainKey,
    sendingChainKey: sending.chainKey,
  };
}

/**
 * Adds retained keys to the store, evicting the oldest entries once full.
 *
 * Eviction rather than refusal, because a message missing for a long time is
 * the one least likely still to arrive, and an adversary should not be able
 * to deny service simply by filling the store.
 */
function retain(session: Session, additions: Map<string, Uint8Array>): void {
  for (const [index, key] of additions) {
    session.skippedKeys.set(index, key);
  }

  while (session.skippedKeys.size > MAX_STORED_KEYS) {
    const oldest = session.skippedKeys.keys().next();
    if (oldest.done === true) {
      break;
    }
    const evicted = session.skippedKeys.get(oldest.value);
    if (evicted !== undefined) {
      wipe(evicted);
    }
    session.skippedKeys.delete(oldest.value);
  }
}

export function decryptMessage(
  session: Session,
  payload: string,
  encodedHeader: string,
  from: string,
  to: string
): string {
  const header = decodeHeader(encodedHeader);
  const ciphertext = fromBase64(payload);

  // --- A message whose key was retained when the chain passed it ----------
  const retainedIndex = skippedKeyIndex(header.dh, header.n);
  const retained = session.skippedKeys.get(retainedIndex);
  if (retained !== undefined) {
    // Decrypted before the key is removed, so a message that fails to
    // authenticate does not consume the key a genuine one will need.
    const plaintext = decrypt(retained, ciphertext, from, to, header);
    wipe(retained);
    session.skippedKeys.delete(retainedIndex);
    return plaintext;
  }

  // --- Otherwise the chains advance, on local values only -----------------
  const pending = new Map<string, Uint8Array>();

  let rootKey = session.rootKey;
  let ratchetKeyPair = session.ratchetKeyPair;
  let sendingChainKey = session.sendingChainKey;
  let receivingChainKey: Uint8Array | null;
  let receiveCounter: number;
  let previousSendingChainLength = session.previousSendingChainLength;
  let sendCounter = session.sendCounter;

  if (header.dh !== session.remoteRatchetKey) {
    // The superseded receiving chain may still owe messages. The header states
    // how long it was, so its remaining keys are derived and retained before
    // the chain is replaced and becomes underivable.
    if (session.receivingChainKey !== null && session.remoteRatchetKey !== null) {
      skipTo(
        session.receivingChainKey,
        session.receiveCounter,
        header.pn,
        session.remoteRatchetKey,
        pending
      );
    }

    const stepped = ratchetStep(session.rootKey, session.ratchetKeyPair, header.dh);
    rootKey = stepped.rootKey;
    ratchetKeyPair = stepped.ratchetKeyPair;
    receivingChainKey = stepped.receivingChainKey;
    sendingChainKey = stepped.sendingChainKey;

    previousSendingChainLength = session.sendCounter;
    sendCounter = 0;
    receiveCounter = 0;
  } else {
    receivingChainKey = session.receivingChainKey;
    receiveCounter = session.receiveCounter;
  }

  if (receivingChainKey === null) {
    throw new Error('No receiving chain established, and this message does not begin one');
  }

  if (header.n < receiveCounter) {
    throw new Error(
      `Message ${header.n} is behind the current chain position (${receiveCounter}) ` +
        'and its key was not retained'
    );
  }

  // Positions between the current one and this message are retained, not
  // discarded: that is what lets those messages be read if they arrive later.
  const walked = skipTo(receivingChainKey, receiveCounter, header.n, header.dh, pending);
  const { messageKey, nextChainKey } = advanceChain(walked);

  let plaintext: string;
  try {
    plaintext = decrypt(messageKey, ciphertext, from, to, header);
  } catch (error) {
    // Nothing has been committed: the session and the store are untouched.
    wipe(messageKey);
    for (const key of pending.values()) {
      wipe(key);
    }
    throw error;
  }

  wipe(messageKey);

  if (session.receivingChainKey !== null) {
    wipe(session.receivingChainKey);
  }
  if (session.sendingChainKey !== null && session.sendingChainKey !== sendingChainKey) {
    wipe(session.sendingChainKey);
  }

  session.rootKey = rootKey;
  session.ratchetKeyPair = ratchetKeyPair;
  session.remoteRatchetKey = header.dh;
  session.sendingChainKey = sendingChainKey;
  session.receivingChainKey = nextChainKey;
  session.sendCounter = sendCounter;
  session.receiveCounter = header.n + 1;
  session.previousSendingChainLength = previousSendingChainLength;
  retain(session, pending);

  return plaintext;
}
