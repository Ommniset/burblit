/**
 * A simplified X3DH key agreement (Marlinspike and Perrin, 2016).
 *
 * The protocol exists to solve a problem a plain Diffie-Hellman cannot: two
 * parties must reach a shared secret when only one of them is online. The
 * recipient publishes key material in advance; the initiator collects it from
 * the registry, derives the root key alone, and sends a header from which the
 * recipient reconstructs the same value whenever it next connects.
 *
 * Three Diffie-Hellman exchanges are combined, and each contributes a distinct
 * property:
 *
 *   DH1 = DH(IK_initiator, SPK_recipient)  authenticates the initiator
 *   DH2 = DH(EK_initiator, IK_recipient)   authenticates the recipient
 *   DH3 = DH(EK_initiator, SPK_recipient)  provides forward secrecy
 *   DH4 = DH(EK_initiator, OPK_recipient)  optional; strengthens DH3
 *
 * DH1 and DH2 each bind one party's long-term identity into the result, so a
 * passive adversary holding neither identity key cannot reach the root key.
 * DH3 and DH4 involve an ephemeral key the initiator discards immediately, so
 * compromise of both identity keys at some later date does not reveal the root
 * key of a session already completed. Concatenating all four and hashing once
 * means every contribution must be correct: an adversary able to compute three
 * of them still learns nothing.
 *
 * DH4 is omitted when the recipient's one-time prekey pool is exhausted, which
 * the specification permits. The session then rests on the signed prekey
 * alone, which is reused across handshakes, so forward secrecy for the initial
 * message is weaker until the ratchet advances.
 *
 * DIVERGENCES FROM THE SPECIFICATION, both recorded in the design chapter:
 *
 * 1. X3DH specifies HKDF-SHA256 for the derivation. libsodium-wrappers does
 *    not reliably expose HKDF, so keyed BLAKE2b is used instead. BLAKE2b is a
 *    secure pseudo-random function and the construction preserves the property
 *    required here, that the output is indistinguishable from random without
 *    knowledge of every input. It is a substitution of primitive, not a
 *    weakening of the construction, but it does mean this implementation is
 *    not wire-compatible with Signal.
 *
 * 2. The associated data that X3DH binds into the derivation, carrying both
 *    parties' identity keys, is included here as the BLAKE2b key rather than
 *    as a separate HKDF info parameter. The binding is preserved; its position
 *    in the construction differs.
 */

import {
  ROOT_KEY_BYTES,
  type AgreementMode,
  type InitiationResult,
  type KeyAgreement,
  type ResponseResult,
} from '../shared/keyAgreement';
import type { PrekeyBundle } from '../shared/protocol';
import { initSodium, sodium, toBase64, fromBase64 } from './crypto';
import {
  identityPrivateToX25519,
  identityPublicToX25519,
  verifyBundle,
  type Identity,
} from './identity';

/**
 * The handshake header.
 *
 * Travels with the first message and is opaque to the relay. It carries no
 * secret: the ephemeral public key is public by construction, and the prekey
 * identifier only names which published key was consumed.
 */
export interface HandshakeHeader {
  /** Protocol version, so a future hybrid header is distinguishable. */
  v: 1;
  mode: AgreementMode;
  /** Initiator's Ed25519 identity key, base64. */
  ik: string;
  /** Initiator's ephemeral X25519 public key, base64. */
  ek: string;
  /** Identifier of the consumed one-time prekey, or null if none was served. */
  opk: number | null;
}

/**
 * Domain separator, so these derivations cannot collide with the ratchet's.
 * Used as a BLAKE2b key, which libsodium requires to be at least
 * crypto_generichash_KEYBYTES_MIN (16) bytes long.
 */
const DERIVATION_CONTEXT = 'Burblit-X3DH-v1-root';

/**
 * Derives the root key from the concatenated Diffie-Hellman outputs.
 *
 * `associatedData` binds both identity keys into the result, which is what
 * prevents an unknown-key-share attack: an adversary who relays a handshake
 * while substituting identities produces a different root key on each side,
 * so the session fails rather than succeeding under a false identity.
 */
function deriveRootKey(dhOutputs: Uint8Array[], associatedData: Uint8Array): Uint8Array {
  const totalLength = dhOutputs.reduce((sum, part) => sum + part.length, 0);
  const concatenated = new Uint8Array(totalLength);

  let offset = 0;
  for (const part of dhOutputs) {
    concatenated.set(part, offset);
    offset += part.length;
  }

  // BLAKE2b accepts a key of at most crypto_generichash_KEYBYTES_MAX; the
  // associated data is hashed down to a fixed length first so that identity
  // keys of any size remain usable.
  const derivationKey = sodium.crypto_generichash(
    sodium.crypto_generichash_KEYBYTES,
    associatedData,
    sodium.from_string(DERIVATION_CONTEXT)
  );

  return sodium.crypto_generichash(ROOT_KEY_BYTES, concatenated, derivationKey);
}

/** Concatenates both identity keys in a fixed order, initiator first. */
function associatedData(initiatorIdentity: Uint8Array, responderIdentity: Uint8Array): Uint8Array {
  const combined = new Uint8Array(initiatorIdentity.length + responderIdentity.length);
  combined.set(initiatorIdentity, 0);
  combined.set(responderIdentity, initiatorIdentity.length);
  return combined;
}

export class X25519Agreement implements KeyAgreement {
  readonly mode: AgreementMode = 'x25519';

  constructor(private readonly identity: Identity) {}

  /**
   * Derives a root key as the initiating party.
   *
   * The bundle's signature is verified first. Skipping that check would let
   * the relay serve its own signed prekey in place of the recipient's and
   * decrypt everything that followed, which is precisely the attack
   * end-to-end encryption exists to prevent.
   */
  async initiate(peerBundle: PrekeyBundle): Promise<InitiationResult> {
    await initSodium();

    if (!(await verifyBundle(peerBundle))) {
      throw new Error(
        `Bundle for ${peerBundle.username} failed signature verification; refusing to proceed`
      );
    }

    const peerIdentityEd = fromBase64(peerBundle.identityKey);
    const peerIdentityX = identityPublicToX25519(peerIdentityEd);
    const peerSignedPrekey = fromBase64(peerBundle.signedPrekey);

    // Ephemeral keypair. Its private half is never stored and goes out of
    // scope when this function returns, which is what forward secrecy rests
    // on: there is nothing left to seize.
    const ephemeral = sodium.crypto_box_keypair();

    const ownIdentityX = identityPrivateToX25519(this.identity.identityKeyPair.privateKey);

    const dhOutputs: Uint8Array[] = [
      sodium.crypto_scalarmult(ownIdentityX, peerSignedPrekey),
      sodium.crypto_scalarmult(ephemeral.privateKey, peerIdentityX),
      sodium.crypto_scalarmult(ephemeral.privateKey, peerSignedPrekey),
    ];

    if (peerBundle.oneTimePrekey !== null) {
      dhOutputs.push(
        sodium.crypto_scalarmult(ephemeral.privateKey, fromBase64(peerBundle.oneTimePrekey))
      );
    }

    const rootKey = deriveRootKey(
      dhOutputs,
      associatedData(this.identity.identityKeyPair.publicKey, peerIdentityEd)
    );

    const header: HandshakeHeader = {
      v: 1,
      mode: this.mode,
      ik: toBase64(this.identity.identityKeyPair.publicKey),
      ek: toBase64(ephemeral.publicKey),
      opk: peerBundle.oneTimePrekeyId,
    };

    return {
      rootKey,
      header: sodium.from_string(JSON.stringify(header)),
    };
  }

  /**
   * Derives the same root key as the responding party.
   *
   * Every exchange is the mirror of the initiator's: the private key the
   * initiator used a public counterpart of, and vice versa. The ordering of
   * the four outputs must match exactly, since the derivation hashes their
   * concatenation.
   */
  async respond(header: Uint8Array): Promise<ResponseResult> {
    await initSodium();

    const parsed = parseHandshakeHeader(header);

    const peerIdentityEd = fromBase64(parsed.ik);
    const peerIdentityX = identityPublicToX25519(peerIdentityEd);
    const peerEphemeral = fromBase64(parsed.ek);

    const ownIdentityX = identityPrivateToX25519(this.identity.identityKeyPair.privateKey);
    const ownSignedPrekey = this.identity.signedPrekeyPair.privateKey;

    const dhOutputs: Uint8Array[] = [
      sodium.crypto_scalarmult(ownSignedPrekey, peerIdentityX),
      sodium.crypto_scalarmult(ownIdentityX, peerEphemeral),
      sodium.crypto_scalarmult(ownSignedPrekey, peerEphemeral),
    ];

    if (parsed.opk !== null) {
      const oneTime = this.identity.oneTimePrekeys[parsed.opk];
      if (oneTime === undefined) {
        // The prekey was consumed by an earlier handshake, or belongs to a
        // bundle this client has since replaced. Either way the exchange
        // cannot be completed, and failing loudly is correct: proceeding
        // would silently derive a different key and corrupt the session.
        throw new Error(`One-time prekey ${parsed.opk} is not held by this client`);
      }
      dhOutputs.push(sodium.crypto_scalarmult(oneTime.privateKey, peerEphemeral));
    }

    const rootKey = deriveRootKey(
      dhOutputs,
      associatedData(peerIdentityEd, this.identity.identityKeyPair.publicKey)
    );

    return { rootKey };
  }
}

/** Narrows an untrusted header. A peer's frame is not trusted to be well formed. */
export function parseHandshakeHeader(header: Uint8Array): HandshakeHeader {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sodium.to_string(header));
  } catch {
    throw new Error('Handshake header is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Handshake header is not an object');
  }

  const candidate = parsed as Record<string, unknown>;

  if (candidate.v !== 1) {
    throw new Error(`Unsupported handshake header version: ${String(candidate.v)}`);
  }
  if (candidate.mode !== 'x25519' && candidate.mode !== 'hybrid') {
    throw new Error('Handshake header names an unknown agreement mode');
  }
  if (typeof candidate.ik !== 'string' || typeof candidate.ek !== 'string') {
    throw new Error('Handshake header is missing key material');
  }
  if (candidate.opk !== null && typeof candidate.opk !== 'number') {
    throw new Error('Handshake header carries an invalid prekey identifier');
  }

  return {
    v: 1,
    mode: candidate.mode,
    ik: candidate.ik,
    ek: candidate.ek,
    opk: candidate.opk,
  };
}

/** Fetches a correspondent's bundle from the registry. */
export async function fetchPeerBundle(username: string): Promise<PrekeyBundle> {
  const response = await fetch(`/keys/${encodeURIComponent(username)}`);
  if (response.status === 404) {
    throw new Error(`${username} has not published key material`);
  }
  if (!response.ok) {
    throw new Error(`Bundle request failed with status ${response.status}`);
  }
  return (await response.json()) as PrekeyBundle;
}
