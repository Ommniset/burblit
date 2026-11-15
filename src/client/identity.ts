/**
 * Long-term key material: generation, local persistence, publication and
 * reconciliation with the registry.
 *
 * X3DH requires the identity key to do two things that no single curve
 * provides: sign the prekey, and participate in Diffie-Hellman. Signal solves
 * this with XEdDSA, which produces Ed25519-style signatures directly from an
 * X25519 key. libsodium does not expose XEdDSA, so this implementation takes
 * the standard alternative: the identity key is an Ed25519 keypair, and both
 * halves are converted to X25519 when a Diffie-Hellman is required. The two
 * representations are the same underlying key, so this preserves the property
 * X3DH depends on, that the key used for the authenticating DH is the key that
 * signed the prekey. The difference from Signal is one of construction rather
 * than of security goal, and is recorded as such in the design chapter.
 *
 * PRIVATE KEYS ARE STORED IN CLEARTEXT IN IndexedDB. This is a structural
 * limitation of browser-based end-to-end encryption, not an oversight. The
 * Web Crypto API can hold non-extractable keys that script cannot read, but
 * libsodium operates on raw key bytes and therefore cannot use them; the two
 * are mutually exclusive. The consequence is that script execution in this
 * origin is equivalent to full compromise of the user's conversations, which
 * is why the cross-site scripting vector in the renderer was removed before
 * any key material existed to steal. The residual risk is analysed in the
 * critical reflection.
 *
 * Material is stored per username. Two tabs of the same browser share one
 * IndexedDB, so a single global record would give every local user the same
 * identity and make a handshake between them meaningless.
 */

import {
  MAX_ONE_TIME_PREKEYS,
  type PrekeyBundle,
  type PublishKeysRequest,
  type PublishKeysResponse,
  type RegistryStatusResponse,
} from '../shared/protocol';
import { initSodium, sodium, toBase64, fromBase64 } from './crypto';

const DB_NAME = 'burblit';
const DB_VERSION = 1;
const STORE_NAME = 'identities';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface Identity {
  username: string;

  /** Ed25519. Published; converted to X25519 for Diffie-Hellman. */
  identityKeyPair: KeyPair;

  /** X25519. Rotated periodically in a production system; fixed here. */
  signedPrekeyPair: KeyPair;

  /** Detached Ed25519 signature over the signed prekey's public key. */
  signedPrekeySignature: Uint8Array;

  /**
   * One-time prekeys, indexed by the identifier the server assigned at
   * publication. The sender names an identifier in the handshake header, and
   * this map is what lets the recipient find the matching private key.
   */
  oneTimePrekeys: Record<number, KeyPair>;
}

// ---------------------------------------------------------------------------
// IndexedDB access
// ---------------------------------------------------------------------------

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME, { keyPath: 'username' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function readIdentity(username: string): Promise<Identity | null> {
  return openDatabase().then(
    (database) =>
      new Promise<Identity | null>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, 'readonly');
        const request = transaction.objectStore(STORE_NAME).get(username);
        request.onsuccess = () => resolve((request.result as Identity | undefined) ?? null);
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => database.close();
      })
  );
}

function writeIdentity(identity: Identity): Promise<void> {
  return openDatabase().then(
    (database) =>
      new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        transaction.objectStore(STORE_NAME).put(identity);
        transaction.oncomplete = () => {
          database.close();
          resolve();
        };
        transaction.onerror = () => reject(transaction.error);
      })
  );
}

/** Discards stored material for a user, forcing regeneration on next connect. */
export function clearIdentity(username: string): Promise<void> {
  return openDatabase().then(
    (database) =>
      new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        transaction.objectStore(STORE_NAME).delete(username);
        transaction.oncomplete = () => {
          database.close();
          resolve();
        };
        transaction.onerror = () => reject(transaction.error);
      })
  );
}

// ---------------------------------------------------------------------------
// Curve conversion
//
// Exported because the handshake needs them on both sides: the initiator
// converts the recipient's published Ed25519 identity key, and the recipient
// converts its own private key.
// ---------------------------------------------------------------------------

export function identityPublicToX25519(ed25519PublicKey: Uint8Array): Uint8Array {
  return sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519PublicKey);
}

export function identityPrivateToX25519(ed25519PrivateKey: Uint8Array): Uint8Array {
  return sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519PrivateKey);
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

export function generateOneTimePrekeys(): KeyPair[] {
  const pairs: KeyPair[] = [];
  for (let i = 0; i < MAX_ONE_TIME_PREKEYS; i += 1) {
    pairs.push(sodium.crypto_box_keypair());
  }
  return pairs;
}

export function generateLongTermMaterial(): {
  identityKeyPair: KeyPair;
  signedPrekeyPair: KeyPair;
  signedPrekeySignature: Uint8Array;
} {
  const signing = sodium.crypto_sign_keypair();
  const identityKeyPair: KeyPair = {
    publicKey: signing.publicKey,
    privateKey: signing.privateKey,
  };

  const signedPrekeyPair = sodium.crypto_box_keypair();

  // The signature is what prevents the relay from substituting its own prekey
  // into a bundle it serves. A client that verifies it will not complete a
  // handshake against key material the claimed identity did not vouch for.
  const signedPrekeySignature = sodium.crypto_sign_detached(
    signedPrekeyPair.publicKey,
    identityKeyPair.privateKey
  );

  return { identityKeyPair, signedPrekeyPair, signedPrekeySignature };
}

// ---------------------------------------------------------------------------
// Registry interaction
// ---------------------------------------------------------------------------

async function registryStatus(username: string): Promise<RegistryStatusResponse | null> {
  const response = await fetch(`/keys/${encodeURIComponent(username)}/status`);
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Registry status check failed with status ${response.status}`);
  }
  return (await response.json()) as RegistryStatusResponse;
}

/**
 * Publishes a bundle and returns the identifiers the server assigned to the
 * one-time prekeys, in publication order.
 */
async function publish(
  username: string,
  identityKeyPair: KeyPair,
  signedPrekeyPair: KeyPair,
  signedPrekeySignature: Uint8Array,
  oneTimePrekeyPairs: KeyPair[]
): Promise<number[]> {

  const body: PublishKeysRequest = {
    username,
    identityKey: toBase64(identityKeyPair.publicKey),
    signedPrekey: toBase64(signedPrekeyPair.publicKey),
    signedPrekeySignature: toBase64(signedPrekeySignature),
    oneTimePrekeys: oneTimePrekeyPairs.map((pair) => toBase64(pair.publicKey)),
  };

  const response = await fetch('/keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Key publication rejected with status ${response.status}`);
  }

  const { oneTimePrekeyIds } = (await response.json()) as PublishKeysResponse;

  if (oneTimePrekeyIds.length !== oneTimePrekeyPairs.length) {
    throw new Error('Server returned an unexpected number of prekey identifiers');
  }

  return oneTimePrekeyIds;
}

function indexById(ids: number[], pairs: KeyPair[]): Record<number, KeyPair> {
  const indexed: Record<number, KeyPair> = {};
  ids.forEach((id, index) => {
    indexed[id] = pairs[index];
  });
  return indexed;
}

/**
 * True when the registry's record of this user is one the stored material can
 * actually service.
 *
 * Both conditions are necessary. The identity key must match, or a
 * correspondent would authenticate against a key this client cannot use. And
 * every prekey the registry is still willing to serve must be held locally,
 * because a republication replaces the batch without touching the identity
 * key: checking the identity key alone would accept a state in which the
 * server hands out identifiers this client has no private key for, and every
 * handshake would then fail at the responding end with no indication of why.
 */
function canService(stored: Identity, status: RegistryStatusResponse | null): boolean {
  if (status === null) {
    return false;
  }
  if (status.identityKey !== toBase64(stored.identityKeyPair.publicKey)) {
    return false;
  }
  return status.availablePrekeyIds.every((id) => stored.oneTimePrekeys[id] !== undefined);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Serialises identity loading per username.
 *
 * Publication is destructive: the server replaces a user's entire prekey batch
 * on each call. Two concurrent loads therefore race, and the loser's batch is
 * deleted from the registry while its identifiers remain in local storage,
 * leaving the client unable to answer any handshake. The user interface can
 * issue concurrent calls easily, for instance from a button and a keyboard
 * shortcut, so the guard belongs here rather than at each call site.
 */
const inFlight = new Map<string, Promise<Identity>>();

export function loadOrCreateIdentity(username: string): Promise<Identity> {
  const existing = inFlight.get(username);
  if (existing !== undefined) {
    return existing;
  }

  const task = resolveIdentity(username);
  inFlight.set(
    username,
    task.finally(() => {
      inFlight.delete(username);
    })
  );
  return task;
}

/**
 * Returns the user's identity, creating or re-registering it as required.
 *
 * Stored material is not trusted on its own. The client's IndexedDB and the
 * server's registry are two independent stores that can diverge: the server's
 * database may be reset, or a batch replaced. When they diverge the failure is
 * silent and unrecoverable, because a correspondent is served a prekey
 * identifier the recipient does not hold and every handshake between the two
 * aborts. Reconciling on each connection turns that permanent failure into a
 * transparent repair.
 *
 * Divergence is repaired by republishing the SAME long-term keys with a fresh
 * batch of one-time prekeys, rather than by generating a new identity. The
 * fingerprint a correspondent may have verified out of band therefore survives
 * a server-side reset, which a full regeneration would silently invalidate.
 */
async function resolveIdentity(username: string): Promise<Identity> {
  await initSodium();

  const stored = await readIdentity(username);

  if (stored !== null) {
    if (canService(stored, await registryStatus(username))) {
      return stored;
    }

    console.warn(`Registry diverged from stored material for ${username}; republishing`);

    const oneTimePrekeyPairs = generateOneTimePrekeys();
    const ids = await publish(
      username,
      stored.identityKeyPair,
      stored.signedPrekeyPair,
      stored.signedPrekeySignature,
      oneTimePrekeyPairs
    );

    const repaired: Identity = {
      ...stored,
      oneTimePrekeys: indexById(ids, oneTimePrekeyPairs),
    };
    await writeIdentity(repaired);
    return repaired;
  }

  const { identityKeyPair, signedPrekeyPair, signedPrekeySignature } = generateLongTermMaterial();
  const oneTimePrekeyPairs = generateOneTimePrekeys();

  const ids = await publish(
    username,
    identityKeyPair,
    signedPrekeyPair,
    signedPrekeySignature,
    oneTimePrekeyPairs
  );

  const identity: Identity = {
    username,
    identityKeyPair,
    signedPrekeyPair,
    signedPrekeySignature,
    oneTimePrekeys: indexById(ids, oneTimePrekeyPairs),
  };

  // Stored only after a successful publication. Persisting first would leave
  // a client holding private keys whose public halves the registry never
  // received, and which no correspondent could ever use.
  await writeIdentity(identity);
  return identity;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Checks that a fetched bundle's signed prekey was vouched for by the identity
 * key published alongside it.
 *
 * This is the check that constrains a malicious relay. It does not establish
 * that the identity key belongs to the named user, which the registry cannot
 * prove: it establishes only that the bundle is internally consistent, so the
 * server cannot splice its own prekey into someone else's bundle and read the
 * conversation. Binding a name to a key requires an out-of-band channel and
 * remains future work.
 */
export async function verifyBundle(bundle: PrekeyBundle): Promise<boolean> {
  await initSodium();
  try {
    return sodium.crypto_sign_verify_detached(
      fromBase64(bundle.signedPrekeySignature),
      fromBase64(bundle.signedPrekey),
      fromBase64(bundle.identityKey)
    );
  } catch {
    // Malformed base64 or a wrong-length key reaches here as an exception.
    return false;
  }
}
