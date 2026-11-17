/**
 * Post-quantum key encapsulation: ML-KEM-768.
 *
 * WHY A KEM AND NOT A DIFFIE-HELLMAN
 *
 * X25519 is a key agreement: both parties contribute a public value and each
 * combines its own private half with the other's public half to reach the
 * same secret. ML-KEM is a key encapsulation mechanism, which works
 * differently and asymmetrically. One party publishes a public key; the other
 * generates a secret, encapsulates it under that key, and sends the resulting
 * ciphertext. The holder of the secret key decapsulates it and recovers the
 * same value. There is no operation corresponding to combining two public
 * keys, which is why the hybrid handshake cannot simply substitute one
 * primitive for the other and has to carry both.
 *
 * WHY ML-KEM-768
 *
 * It is the parameter set NIST describes as the general-purpose choice, at
 * security category 3. ML-KEM-512 would halve the key and ciphertext sizes
 * but sits at category 1, which is weaker than the X25519 half of the hybrid
 * already provides and would make the post-quantum component the limiting
 * factor. ML-KEM-1024 costs more bandwidth for protection beyond what this
 * prototype's threat model asks for.
 *
 * THE COST, WHICH IS THE POINT OF MEASURING IT
 *
 * An ML-KEM-768 public key is 1184 bytes and a ciphertext is 1088, against 32
 * bytes for an X25519 public key. The handshake header therefore grows by
 * roughly a factor of thirty-five. That is the central trade-off of the
 * post-quantum transition and the reason the benchmarks exist: the shared
 * secret is the same 32 bytes either way, so everything downstream of the
 * handshake is unchanged, and the cost is paid entirely in the exchange.
 *
 * WHY THE LIBRARY IS INJECTED RATHER THAN IMPORTED
 *
 * `@oqs/liboqs-js` publishes no CommonJS entry point, so a direct import
 * would compile to a `require` that cannot load it, and the module would be
 * usable from the bundled client but not from the test suite. Receiving the
 * factory from the caller keeps both working: the browser supplies it from
 * the application's entry point, and the tests supply it through a dynamic
 * import. The type is imported with `import type`, which the compiler erases,
 * so no runtime dependency is introduced by it.
 *
 * The result is that this module depends on the capability rather than on the
 * package, which is also what would allow the implementation to be swapped
 * for another without touching anything above it.
 *
 * MEMORY
 *
 * The implementation is WebAssembly, and WASM memory is not reclaimed by the
 * garbage collector. The instance is created once and kept for the lifetime
 * of the page rather than per operation, which avoids both the repeated
 * initialisation cost and the leak that creating one per handshake would
 * produce.
 */

import type { MLKEM768 } from '@oqs/liboqs-js';

/** Sizes in bytes, from the algorithm's own metadata. Asserted on first use. */
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
export const ML_KEM_768_SHARED_SECRET_BYTES = 32;

export interface KemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Encapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

/** Produces an initialised ML-KEM-768 instance. */
export type MlKemFactory = () => Promise<MLKEM768>;

let factory: MlKemFactory | null = null;
let instance: Promise<MLKEM768> | null = null;

/**
 * Supplies the implementation. Called once, at the application's entry point
 * or at the start of a test run.
 */
export function useMlKemFactory(supplied: MlKemFactory): void {
  factory = supplied;
  instance = null;
}

/**
 * Resolves the shared instance, initialising it on first use.
 *
 * Memoised for the same reason `initSodium` is: the WebAssembly module must
 * be instantiated before any call, and several independent parts of the
 * client will need it.
 */
export function initMlKem(): Promise<MLKEM768> {
  if (factory === null) {
    throw new Error('No ML-KEM implementation supplied; call useMlKemFactory first');
  }
  if (instance === null) {
    instance = factory();
  }
  return instance;
}

/**
 * Releases the WebAssembly instance.
 *
 * Only required where instances would otherwise accumulate, such as between
 * test runs; the browser client holds one for the lifetime of the page.
 */
export async function releaseMlKem(): Promise<void> {
  if (instance === null) {
    return;
  }
  const kem = await instance;
  instance = null;
  kem.destroy();
}

export async function generateKemKeyPair(): Promise<KemKeyPair> {
  const kem = await initMlKem();
  return kem.generateKeyPair();
}

/**
 * Generates a shared secret and encapsulates it under the recipient's public
 * key. Performed by the initiating party.
 */
export async function encapsulate(publicKey: Uint8Array): Promise<Encapsulation> {
  if (publicKey.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
    throw new Error(
      `Expected a ${ML_KEM_768_PUBLIC_KEY_BYTES}-byte ML-KEM public key, ` +
        `received ${publicKey.length}`
    );
  }
  const kem = await initMlKem();
  return kem.encapsulate(publicKey);
}

/**
 * Recovers the shared secret from a ciphertext. Performed by the responding
 * party, which holds the secret key.
 */
export async function decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  if (ciphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new Error(
      `Expected a ${ML_KEM_768_CIPHERTEXT_BYTES}-byte ML-KEM ciphertext, ` +
        `received ${ciphertext.length}`
    );
  }
  const kem = await initMlKem();
  return kem.decapsulate(ciphertext, secretKey);
}

/**
 * Verifies that encapsulation works end to end in this environment.
 *
 * Generating a keypair alone would establish only that the module loaded.
 * What the hybrid handshake depends on is that the encapsulating and
 * decapsulating parties reach the same secret, so the test performs a
 * complete round trip and compares the results. It also checks the sizes
 * against the constants above, which the header parsing relies on.
 *
 * Returns the shared secret and the time taken, so the caller can report both.
 */
export async function verifyMlKemExchange(): Promise<{
  sharedSecret: Uint8Array;
  elapsedMs: number;
}> {
  const kem = await initMlKem();

  const started = performance.now();
  const { publicKey, secretKey } = kem.generateKeyPair();
  const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
  const recovered = kem.decapsulate(ciphertext, secretKey);
  const elapsedMs = performance.now() - started;

  if (
    publicKey.length !== ML_KEM_768_PUBLIC_KEY_BYTES ||
    secretKey.length !== ML_KEM_768_SECRET_KEY_BYTES ||
    ciphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES ||
    sharedSecret.length !== ML_KEM_768_SHARED_SECRET_BYTES
  ) {
    throw new Error('ML-KEM-768 produced values of unexpected length');
  }

  if (
    recovered.length !== sharedSecret.length ||
    !sharedSecret.every((byte, index) => byte === recovered[index])
  ) {
    throw new Error('ML-KEM smoke test failed: the two parties derived different secrets');
  }

  return { sharedSecret, elapsedMs };
}
