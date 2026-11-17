/**
 * The hybrid key agreement.
 *
 * What matters here is not that ML-KEM works, which the library's own test
 * vectors establish, but that combining it with X3DH produces a root key
 * depending on both components and on nothing else. The tests therefore
 * concentrate on the junction: that both parties agree, that removing either
 * contribution changes the result, and that the hybrid satisfies the same
 * interface as the classical agreement so the ratchet above it cannot tell
 * them apart.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { initSodium, sodium, toBase64, fromBase64 } = require('../dist-test/client/crypto');
const { useMlKemFactory, releaseMlKem, ML_KEM_768_CIPHERTEXT_BYTES } =
  require('../dist-test/client/pqc');
const {
  generateLongTermMaterial,
  generateOneTimePrekeys,
  generateKemMaterial,
} = require('../dist-test/client/identity');
const { X25519Agreement } = require('../dist-test/client/x25519Agreement');
const {
  HybridAgreement,
  parseHybridHeader,
  supportsHybrid,
} = require('../dist-test/client/hybridAgreement');

const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** Builds an identity without touching the registry or any browser storage. */
async function makeIdentity(username) {
  const { identityKeyPair, signedPrekeyPair, signedPrekeySignature } = generateLongTermMaterial();
  const { kemKeyPair, kemPrekeySignature } = await generateKemMaterial(
    identityKeyPair.privateKey
  );

  const oneTimePrekeyPairs = generateOneTimePrekeys();
  const oneTimePrekeys = {};
  oneTimePrekeyPairs.forEach((pair, index) => {
    oneTimePrekeys[index + 1] = pair;
  });

  return {
    username,
    identityKeyPair,
    signedPrekeyPair,
    signedPrekeySignature,
    oneTimePrekeys,
    kemKeyPair,
    kemPrekeySignature,
  };
}

/** The bundle the registry would serve for an identity. */
function bundleFor(identity, { withOneTimePrekey = true, withKem = true } = {}) {
  return {
    username: identity.username,
    identityKey: toBase64(identity.identityKeyPair.publicKey),
    signedPrekey: toBase64(identity.signedPrekeyPair.publicKey),
    signedPrekeySignature: toBase64(identity.signedPrekeySignature),
    oneTimePrekey: withOneTimePrekey ? toBase64(identity.oneTimePrekeys[1].publicKey) : null,
    oneTimePrekeyId: withOneTimePrekey ? 1 : null,
    kemPrekey: withKem ? toBase64(identity.kemKeyPair.publicKey) : null,
    kemPrekeySignature: withKem ? toBase64(identity.kemPrekeySignature) : null,
  };
}

test.before(async () => {
  await initSodium();
  const liboqs = await import('@oqs/liboqs-js');
  useMlKemFactory(liboqs.createMLKEM768);
});

test.after(async () => {
  await releaseMlKem();
});

// ---------------------------------------------------------------------------
// Agreement
// ---------------------------------------------------------------------------

test('both parties derive an identical root key', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const initiated = await new HybridAgreement(alice).initiate(bundleFor(bob));
  const responded = await new HybridAgreement(bob).respond(initiated.header);

  assert.equal(initiated.rootKey.length, 32);
  assert.equal(hex(initiated.rootKey), hex(responded.rootKey));
});

test('the agreement works without a one-time prekey', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  // An exhausted pool costs forward secrecy for the first message but must
  // not prevent the handshake, or exhaustion becomes a denial of service.
  const bundle = bundleFor(bob, { withOneTimePrekey: false });
  const initiated = await new HybridAgreement(alice).initiate(bundle);
  const responded = await new HybridAgreement(bob).respond(initiated.header);

  assert.equal(hex(initiated.rootKey), hex(responded.rootKey));
});

test('each handshake produces a different root key', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');
  const seen = new Set();

  // The ephemeral key and the encapsulation are both fresh each time, so
  // repeating a handshake against the same bundle must not repeat the key.
  for (let i = 0; i < 10; i += 1) {
    const { rootKey } = await new HybridAgreement(alice).initiate(
      bundleFor(bob, { withOneTimePrekey: false })
    );
    assert.ok(!seen.has(hex(rootKey)), `root key repeated at handshake ${i}`);
    seen.add(hex(rootKey));
  }
});

// ---------------------------------------------------------------------------
// The hybrid property
// ---------------------------------------------------------------------------

test('the hybrid root key differs from the classical one for the same parties', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');
  const bundle = bundleFor(bob, { withOneTimePrekey: false });

  const classical = await new X25519Agreement(alice).initiate(bundle);
  const hybrid = await new HybridAgreement(alice).initiate(bundle);

  // Distinct domain separators as well as distinct inputs: the two
  // constructions must not be able to produce the same key from related
  // material, or a downgrade would be undetectable at the key level.
  assert.notEqual(hex(classical.rootKey), hex(hybrid.rootKey));
});

test('altering the encapsulation changes the responder key', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const initiated = await new HybridAgreement(alice).initiate(bundleFor(bob));
  const header = JSON.parse(Buffer.from(initiated.header).toString('utf8'));

  const ciphertext = fromBase64(header.ct);
  ciphertext[0] ^= 0x01;
  header.ct = toBase64(ciphertext);

  // ML-KEM performs implicit rejection: decapsulation of a corrupted
  // ciphertext returns an unrelated value rather than failing, which denies
  // an adversary an oracle. The handshake therefore cannot detect tampering
  // here; the two sides simply disagree, and the first message's
  // authenticator is what surfaces it.
  const responded = await new HybridAgreement(bob).respond(
    sodium.from_string(JSON.stringify(header))
  );

  assert.notEqual(hex(initiated.rootKey), hex(responded.rootKey));
});

test('a responder without a post-quantum key cannot answer', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const initiated = await new HybridAgreement(alice).initiate(bundleFor(bob));

  const withoutKem = { ...bob };
  delete withoutKem.kemKeyPair;

  await assert.rejects(
    () => new HybridAgreement(withoutKem).respond(initiated.header),
    /holds no post-quantum key/
  );
});

// ---------------------------------------------------------------------------
// Bundle validation
// ---------------------------------------------------------------------------

test('a bundle without post-quantum material is reported as classical-only', async () => {
  const bob = await makeIdentity('bob');

  assert.equal(supportsHybrid(bundleFor(bob)), true);
  assert.equal(supportsHybrid(bundleFor(bob, { withKem: false })), false);
});

test('a hybrid handshake against a classical-only bundle is refused', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  await assert.rejects(
    () => new HybridAgreement(alice).initiate(bundleFor(bob, { withKem: false })),
    /has published no post-quantum key/
  );
});

test('a bundle whose post-quantum key was substituted is refused', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');
  const relay = await makeIdentity('relay');

  // The attack the signature exists to stop: the relay serves its own
  // encapsulation key, recovers the post-quantum secret, and the hybrid
  // degrades silently to classical-only security.
  const tampered = bundleFor(bob);
  tampered.kemPrekey = toBase64(relay.kemKeyPair.publicKey);

  await assert.rejects(
    () => new HybridAgreement(alice).initiate(tampered),
    /failed signature verification/
  );
});

test('a bundle carrying an unsigned post-quantum key is refused', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  // Stripping the signature must not be a way to downgrade verification.
  const tampered = bundleFor(bob);
  tampered.kemPrekeySignature = null;

  await assert.rejects(
    () => new HybridAgreement(alice).initiate(tampered),
    /failed signature verification/
  );
});

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

test('the header is rejected when the encapsulation is the wrong length', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const initiated = await new HybridAgreement(alice).initiate(bundleFor(bob));
  const header = JSON.parse(Buffer.from(initiated.header).toString('utf8'));
  header.ct = toBase64(new Uint8Array(32));

  assert.throws(
    () => parseHybridHeader(sodium.from_string(JSON.stringify(header))),
    /ML-KEM-768 produces 1088/
  );
});

test('the header carries the encapsulation and is dominated by it', async () => {
  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const classical = await new X25519Agreement(alice).initiate(bundleFor(bob));
  const hybrid = await new HybridAgreement(alice).initiate(bundleFor(bob));

  const parsed = parseHybridHeader(hybrid.header);
  assert.equal(fromBase64(parsed.ct).length, ML_KEM_768_CIPHERTEXT_BYTES);

  // The figure the benchmarks will quantify: the shared secret is the same
  // size either way, and the entire cost of the hybrid is paid in the
  // exchange.
  const growth = hybrid.header.length / classical.header.length;
  assert.ok(growth > 5, `the hybrid header should be substantially larger, saw ${growth}x`);
});