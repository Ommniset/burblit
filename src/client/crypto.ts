/**
 * libsodium bootstrap and encoding helpers for the browser client.
 *
 * The interim report recorded libsodium as unusable in the browser. The
 * obstacle was not the library but the loading method: it was being pulled
 * from a content delivery network, and the browser's tracking protection
 * blocked the request. Imported as a module and bundled into the application's
 * own script, the browser never makes an external request at all and the
 * problem disappears. The dependency was already present in package.json
 * throughout.
 *
 * All key material crossing the wire is encoded with the ORIGINAL base64
 * variant, matching the validation pattern in the shared protocol module.
 * libsodium defaults to URLSAFE_NO_PADDING, which would be silently rejected
 * by the server, so the variant is stated explicitly at every call site rather
 * than left to the default.
 */

import sodium from 'libsodium-wrappers';

let ready: Promise<void> | null = null;

/**
 * Resolves once the WebAssembly module is initialised.
 *
 * Memoised, because `sodium.ready` must be awaited before any other call and
 * several independent parts of the client will need it. Calling any primitive
 * before this resolves yields undefined behaviour rather than an error, which
 * is a difficult failure to diagnose.
 */
export function initSodium(): Promise<void> {
  if (ready === null) {
    ready = sodium.ready;
  }
  return ready;
}

export function toBase64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(text: string): Uint8Array {
  return sodium.from_base64(text, sodium.base64_variants.ORIGINAL);
}

/**
 * Verifies that X25519 Diffie-Hellman works end to end in this browser.
 *
 * Generating a keypair alone would only prove that the module loaded. The test
 * performs a full exchange between two locally generated keypairs and asserts
 * that both sides reach the same shared secret, which is the exact primitive
 * day 6 depends on. Comparison uses libsodium's constant-time `memcmp` rather
 * than a loop; the timing of this particular comparison is not sensitive, but
 * establishing the habit here avoids writing a variable-time comparison
 * somewhere it does matter.
 *
 * Returns the shared secret so the caller can display it as evidence.
 */
export async function verifyX25519Exchange(): Promise<Uint8Array> {
  await initSodium();

  // crypto_box keypairs are X25519 keypairs.
  const alice = sodium.crypto_box_keypair();
  const bob = sodium.crypto_box_keypair();

  const aliceView = sodium.crypto_scalarmult(alice.privateKey, bob.publicKey);
  const bobView = sodium.crypto_scalarmult(bob.privateKey, alice.publicKey);

  if (!sodium.memcmp(aliceView, bobView)) {
    throw new Error('X25519 smoke test failed: the two parties derived different secrets');
  }

  return aliceView;
}

export { sodium };
