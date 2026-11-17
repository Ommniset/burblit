/**
 * A hybrid classical and post-quantum key agreement.
 *
 * WHAT HYBRID MEANS, AND WHY
 *
 * The root key is derived from both an X3DH exchange and an ML-KEM
 * encapsulation, concatenated into a single derivation. The resulting secret
 * is safe as long as at least one of the two underlying problems is hard, so
 * the construction can only improve on either component alone: an adversary
 * must break both the elliptic-curve discrete logarithm and module lattices
 * to recover it.
 *
 * That asymmetry of risk is the entire argument for hybrids during a
 * transition. X25519 has two decades of analysis behind it and a known
 * weakness against a sufficiently large quantum computer. ML-KEM resists that
 * attack but is comparatively young, and the history of post-quantum
 * candidates includes schemes broken late in their evaluation, SIKE most
 * prominently. Deploying either alone means accepting one of those risks
 * whole; deploying both means accepting neither.
 *
 * THE THREAT THIS ADDRESSES
 *
 * The attack is not hypothetical and does not require a quantum computer to
 * exist today. An adversary can record encrypted traffic now and decrypt it
 * once the capability arrives, which is why messages whose confidentiality
 * must outlast the hardware need post-quantum protection at the time they are
 * sent rather than later.
 *
 * WHY THE TWO PRIMITIVES ARE NOT INTERCHANGEABLE
 *
 * X25519 is a key agreement: both parties publish a value and each combines
 * its private half with the other's public half. ML-KEM is a key
 * encapsulation mechanism, which is asymmetric: the recipient publishes a
 * public key, the sender generates a secret and encapsulates it, and the
 * recipient decapsulates. There is no operation that combines two ML-KEM
 * public keys, so the hybrid cannot substitute one for the other. It carries
 * both, and the extra traffic is almost entirely the KEM ciphertext.
 *
 * WHAT IMPLICIT REJECTION MEANS HERE
 *
 * ML-KEM does not report a corrupted ciphertext as an error. It performs
 * implicit rejection, returning a deterministic but unrelated value, which
 * denies an adversary the oracle a distinguishable failure would provide. The
 * handshake therefore cannot learn from decapsulation whether the exchange
 * was tampered with: the two parties simply derive different root keys, and
 * the discrepancy surfaces when the first message fails to authenticate.
 *
 * SIMPLIFICATION AGAINST THE SPECIFICATION
 *
 * Signal's PQXDH publishes one-time KEM prekeys alongside a signed one. Here
 * only the signed key is published, so the post-quantum component of the
 * initial message is not covered by forward secrecy of its own: an adversary
 * who later obtained the KEM secret key could recover the post-quantum half
 * of a recorded handshake. The classical half retains its forward secrecy,
 * and the ratchet supersedes both after the first exchange. This is recorded
 * in the critical reflection rather than presented as equivalent to the
 * specification.
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
import { decapsulate, encapsulate, initMlKem, ML_KEM_768_CIPHERTEXT_BYTES } from './pqc';

/**
 * The hybrid handshake header.
 *
 * Identical to the classical header except for `ct`, the ML-KEM ciphertext,
 * which is 1088 bytes and dominates the size of the whole structure. Nothing
 * in it is secret: a ciphertext is meaningless without the secret key that
 * decapsulates it.
 */
export interface HybridHandshakeHeader {
  v: 1;
  mode: 'hybrid';
  /** Initiator's Ed25519 identity key, base64. */
  ik: string;
  /** Initiator's ephemeral X25519 public key, base64. */
  ek: string;
  /** Identifier of the consumed one-time prekey, or null if none was served. */
  opk: number | null;
  /** ML-KEM-768 ciphertext encapsulating the post-quantum secret, base64. */
  ct: string;
}

/**
 * Domain separator. Distinct from the classical one, so the two constructions
 * cannot produce the same root key from related inputs.
 */
const DERIVATION_CONTEXT = 'Burblit-PQXDH-v1-root';

/**
 * Derives the root key from the concatenated exchange outputs.
 *
 * The post-quantum secret is appended to the Diffie-Hellman outputs and the
 * whole sequence hashed once, which is what makes the result depend on every
 * component: an adversary who recovers all four Diffie-Hellman values but not
 * the encapsulated secret learns nothing, and the converse holds as well.
 */
function deriveRootKey(contributions: Uint8Array[], associatedData: Uint8Array): Uint8Array {
  const totalLength = contributions.reduce((sum, part) => sum + part.length, 0);
  const concatenated = new Uint8Array(totalLength);

  let offset = 0;
  for (const part of contributions) {
    concatenated.set(part, offset);
    offset += part.length;
  }

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

/** True when a correspondent has published the material a hybrid handshake needs. */
export function supportsHybrid(bundle: PrekeyBundle): boolean {
  return bundle.kemPrekey !== null && bundle.kemPrekeySignature !== null;
}

export class HybridAgreement implements KeyAgreement {
  readonly mode: AgreementMode = 'hybrid';

  constructor(private readonly identity: Identity) {}

  async initiate(peerBundle: PrekeyBundle): Promise<InitiationResult> {
    await initSodium();
    await initMlKem();

    if (!(await verifyBundle(peerBundle))) {
      throw new Error(
        `Bundle for ${peerBundle.username} failed signature verification; refusing to proceed`
      );
    }

    if (peerBundle.kemPrekey === null) {
      throw new Error(
        `${peerBundle.username} has published no post-quantum key; a hybrid handshake ` +
          'is not available with this correspondent'
      );
    }

    const peerIdentityEd = fromBase64(peerBundle.identityKey);
    const peerIdentityX = identityPublicToX25519(peerIdentityEd);
    const peerSignedPrekey = fromBase64(peerBundle.signedPrekey);

    // Ephemeral keypair. Its private half is never stored and goes out of
    // scope when this function returns, which is what the classical half of
    // the forward secrecy rests on.
    const ephemeral = sodium.crypto_box_keypair();
    const ownIdentityX = identityPrivateToX25519(this.identity.identityKeyPair.privateKey);

    const contributions: Uint8Array[] = [
      sodium.crypto_scalarmult(ownIdentityX, peerSignedPrekey),
      sodium.crypto_scalarmult(ephemeral.privateKey, peerIdentityX),
      sodium.crypto_scalarmult(ephemeral.privateKey, peerSignedPrekey),
    ];

    if (peerBundle.oneTimePrekey !== null) {
      contributions.push(
        sodium.crypto_scalarmult(ephemeral.privateKey, fromBase64(peerBundle.oneTimePrekey))
      );
    }

    // The post-quantum contribution. The secret is generated here and never
    // transmitted; only the ciphertext travels, and it is useless without the
    // recipient's secret key.
    const { ciphertext, sharedSecret } = await encapsulate(fromBase64(peerBundle.kemPrekey));
    contributions.push(sharedSecret);

    const rootKey = deriveRootKey(
      contributions,
      associatedData(this.identity.identityKeyPair.publicKey, peerIdentityEd)
    );

    const header: HybridHandshakeHeader = {
      v: 1,
      mode: 'hybrid',
      ik: toBase64(this.identity.identityKeyPair.publicKey),
      ek: toBase64(ephemeral.publicKey),
      opk: peerBundle.oneTimePrekeyId,
      ct: toBase64(ciphertext),
    };

    return { rootKey, header: sodium.from_string(JSON.stringify(header)) };
  }

  async respond(header: Uint8Array): Promise<ResponseResult> {
    await initSodium();
    await initMlKem();

    const parsed = parseHybridHeader(header);

    if (this.identity.kemKeyPair === undefined) {
      throw new Error('This client holds no post-quantum key and cannot answer a hybrid handshake');
    }

    const peerIdentityEd = fromBase64(parsed.ik);
    const peerIdentityX = identityPublicToX25519(peerIdentityEd);
    const peerEphemeral = fromBase64(parsed.ek);

    const ownIdentityX = identityPrivateToX25519(this.identity.identityKeyPair.privateKey);
    const ownSignedPrekey = this.identity.signedPrekeyPair.privateKey;

    // Each exchange mirrors the initiator's, and the ordering must match
    // exactly, since the derivation hashes their concatenation.
    const contributions: Uint8Array[] = [
      sodium.crypto_scalarmult(ownSignedPrekey, peerIdentityX),
      sodium.crypto_scalarmult(ownIdentityX, peerEphemeral),
      sodium.crypto_scalarmult(ownSignedPrekey, peerEphemeral),
    ];

    if (parsed.opk !== null) {
      const oneTime = this.identity.oneTimePrekeys[parsed.opk];
      if (oneTime === undefined) {
        throw new Error(`One-time prekey ${parsed.opk} is not held by this client`);
      }
      contributions.push(sodium.crypto_scalarmult(oneTime.privateKey, peerEphemeral));
    }

    // Decapsulation cannot report a corrupted ciphertext: a wrong value simply
    // produces a different secret, and therefore a different root key, which
    // the first message's authenticator detects.
    contributions.push(
      await decapsulate(fromBase64(parsed.ct), this.identity.kemKeyPair.secretKey)
    );

    const rootKey = deriveRootKey(
      contributions,
      associatedData(peerIdentityEd, this.identity.identityKeyPair.publicKey)
    );

    return { rootKey };
  }
}

/** Narrows an untrusted header. A peer's frame is not trusted to be well formed. */
export function parseHybridHeader(header: Uint8Array): HybridHandshakeHeader {
  let parsed: unknown;
  try {
    parsed = JSON.parse(sodium.to_string(header));
  } catch {
    throw new Error('Hybrid handshake header is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Hybrid handshake header is not an object');
  }

  const candidate = parsed as Record<string, unknown>;

  if (candidate.v !== 1) {
    throw new Error(`Unsupported handshake header version: ${String(candidate.v)}`);
  }
  if (candidate.mode !== 'hybrid') {
    throw new Error('Handshake header does not name the hybrid agreement');
  }
  if (typeof candidate.ik !== 'string' || typeof candidate.ek !== 'string') {
    throw new Error('Handshake header is missing key material');
  }
  if (typeof candidate.ct !== 'string') {
    throw new Error('Handshake header carries no encapsulation');
  }
  if (candidate.opk !== null && typeof candidate.opk !== 'number') {
    throw new Error('Handshake header carries an invalid prekey identifier');
  }

  // Checked before the value reaches the library, so a malformed header is
  // rejected with a useful message rather than failing inside WebAssembly.
  const ciphertextLength = fromBase64(candidate.ct).length;
  if (ciphertextLength !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new Error(
      `Handshake header carries a ${ciphertextLength}-byte encapsulation; ` +
        `ML-KEM-768 produces ${ML_KEM_768_CIPHERTEXT_BYTES}`
    );
  }

  return {
    v: 1,
    mode: 'hybrid',
    ik: candidate.ik,
    ek: candidate.ek,
    opk: candidate.opk,
    ct: candidate.ct,
  };
}
