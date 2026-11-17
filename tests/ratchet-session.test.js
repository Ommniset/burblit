/**
 * The Double Ratchet, exercised as two parties.
 *
 * Both sides are driven here in one process, which is what makes the
 * synchronisation testable at all: a conversation held between two browser
 * tabs can only be inspected after it has already gone wrong, and the state
 * that matters is held in memory on each side.
 *
 * No server is involved. The handshake is replaced by a shared root key and a
 * signed prekey pair, because what is under test is the ratchet, not the key
 * agreement.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { initSodium, sodium, toBase64 } = require('../dist-test/client/crypto');
const {
  initiatorSession,
  responderSession,
  encryptMessage,
  decryptMessage,
  decodeHeader,
  MAX_SKIPPED_MESSAGES,
} = require('../dist-test/client/session');

const ALICE = 'alice';
const BOB = 'bob';

const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** A pair of sessions, as the handshake would leave them. */
function establish() {
  const rootKey = new Uint8Array(32).fill(42);
  const signedPrekeyPair = sodium.crypto_box_keypair();

  return {
    alice: initiatorSession(BOB, rootKey, toBase64(signedPrekeyPair.publicKey), 'handshake'),
    bob: responderSession(ALICE, rootKey, signedPrekeyPair),
  };
}

/** Sends one message and delivers it, returning the plaintext recovered. */
function exchange(sender, receiver, from, to, plaintext) {
  const { payload, header } = encryptMessage(sender, plaintext, from, to);
  return decryptMessage(receiver, payload, header, from, to);
}

/**
 * A complete copy of a session's state, as an adversary seizing the device
 * would obtain.
 */
function snapshot(session) {
  return {
    ...session,
    rootKey: Uint8Array.from(session.rootKey),
    ratchetKeyPair: {
      publicKey: Uint8Array.from(session.ratchetKeyPair.publicKey),
      privateKey: Uint8Array.from(session.ratchetKeyPair.privateKey),
    },
    sendingChainKey:
      session.sendingChainKey === null ? null : Uint8Array.from(session.sendingChainKey),
    receivingChainKey:
      session.receivingChainKey === null ? null : Uint8Array.from(session.receivingChainKey),
  };
}

test.before(async () => {
  await initSodium();
});

// ---------------------------------------------------------------------------
// Establishment
// ---------------------------------------------------------------------------

test('the initiator can send before the responder has any chain', async () => {
  const { alice, bob } = establish();

  // The asynchronous case: the responder has never been online, and its
  // published signed prekey is what lets the initiator ratchet immediately.
  assert.notEqual(alice.sendingChainKey, null);
  assert.equal(bob.sendingChainKey, null);
  assert.equal(bob.receivingChainKey, null);

  assert.equal(exchange(alice, bob, ALICE, BOB, 'first contact'), 'first contact');
});

test('the responder gains both chains on the first message received', async () => {
  const { alice, bob } = establish();

  assert.throws(() => encryptMessage(bob, 'too early', BOB, ALICE), /No sending chain/);

  exchange(alice, bob, ALICE, BOB, 'first contact');

  assert.notEqual(bob.sendingChainKey, null);
  assert.notEqual(bob.receivingChainKey, null);
  assert.equal(exchange(bob, alice, BOB, ALICE, 'reply'), 'reply');
});

test('a hundred messages in one direction all decrypt', async () => {
  const { alice, bob } = establish();

  for (let i = 0; i < 100; i += 1) {
    assert.equal(exchange(alice, bob, ALICE, BOB, `message ${i}`), `message ${i}`);
  }
  assert.equal(alice.sendCounter, 100);
});

test('an alternating conversation survives fifty turns', async () => {
  const { alice, bob } = establish();

  for (let i = 0; i < 50; i += 1) {
    assert.equal(exchange(alice, bob, ALICE, BOB, `alice ${i}`), `alice ${i}`);
    assert.equal(exchange(bob, alice, BOB, ALICE, `bob ${i}`), `bob ${i}`);
  }
});

// ---------------------------------------------------------------------------
// The Diffie-Hellman ratchet
// ---------------------------------------------------------------------------

test('a reply carries a new ratchet key and advances the root chain', async () => {
  const { alice, bob } = establish();

  const rootBefore = hex(alice.rootKey);
  const keyBefore = hex(alice.ratchetKeyPair.publicKey);

  exchange(alice, bob, ALICE, BOB, 'hello');
  exchange(bob, alice, BOB, ALICE, 'hello back');

  // Receiving a key it had not seen causes a ratchet step: a new root key, a
  // new keypair of its own, and fresh chains in both directions.
  assert.notEqual(hex(alice.rootKey), rootBefore);
  assert.notEqual(hex(alice.ratchetKeyPair.publicKey), keyBefore);
});

test('successive turns never reuse a ratchet key', async () => {
  const { alice, bob } = establish();

  // Every key either party has ever advertised. A repeat would mean a turn
  // contributed no new entropy, and break-in recovery depends on each one
  // doing so.
  const seen = new Set([
    hex(alice.ratchetKeyPair.publicKey),
    hex(bob.ratchetKeyPair.publicKey),
  ]);

  for (let turn = 0; turn < 20; turn += 1) {
    exchange(alice, bob, ALICE, BOB, `alice ${turn}`);
    exchange(bob, alice, BOB, ALICE, `bob ${turn}`);

    const aliceKey = hex(alice.ratchetKeyPair.publicKey);
    const bobKey = hex(bob.ratchetKeyPair.publicKey);

    assert.ok(!seen.has(aliceKey), `alice reused a ratchet key at turn ${turn}`);
    seen.add(aliceKey);

    assert.ok(!seen.has(bobKey), `bob reused a ratchet key at turn ${turn}`);
    seen.add(bobKey);
  }

  // Two fresh keys per turn, plus the two the session began with.
  assert.equal(seen.size, 42);
});

test('a seized session loses the conversation after two further turns', async () => {
  const { alice, bob } = establish();

  exchange(alice, bob, ALICE, BOB, 'opening');
  exchange(bob, alice, BOB, ALICE, 'reply');

  // The adversary takes a complete copy of the device state and continues to
  // observe every frame. Nothing is hidden from it at this point, including
  // the ratchet private key Alice has just generated.
  const seized = snapshot(alice);

  // Turn one. Bob has not changed his ratchet key, so no step occurs and the
  // copy follows without difficulty.
  let sent = encryptMessage(bob, 'still readable', BOB, ALICE);
  assert.equal(decryptMessage(alice, sent.payload, sent.header, BOB, ALICE), 'still readable');
  assert.equal(decryptMessage(seized, sent.payload, sent.header, BOB, ALICE), 'still readable');

  exchange(alice, bob, ALICE, BOB, 'alice advertises her current key');

  // Turn two. Bob has ratcheted, so Alice steps as well. The new receiving
  // chain descends from the private key Alice held when the state was seized,
  // which the adversary therefore also holds: it still follows. Recovery is
  // not instant, and claiming otherwise would overstate the property.
  sent = encryptMessage(bob, 'still readable too', BOB, ALICE);
  assert.equal(
    decryptMessage(alice, sent.payload, sent.header, BOB, ALICE),
    'still readable too'
  );
  assert.equal(
    decryptMessage(seized, sent.payload, sent.header, BOB, ALICE),
    'still readable too'
  );

  // That step, however, generated a fresh keypair on each side independently:
  // Alice's is one the adversary never saw, and the copy generated a
  // different one of its own. Once Bob ratchets against Alice's genuine key,
  // the two diverge irrecoverably.
  exchange(alice, bob, ALICE, BOB, 'alice advertises the key the adversary lacks');

  sent = encryptMessage(bob, 'no longer readable', BOB, ALICE);
  assert.equal(
    decryptMessage(alice, sent.payload, sent.header, BOB, ALICE),
    'no longer readable'
  );
  assert.throws(
    () => decryptMessage(seized, sent.payload, sent.header, BOB, ALICE),
    'the seized state must not be able to read messages sent after recovery'
  );
});

// ---------------------------------------------------------------------------
// Forward secrecy
// ---------------------------------------------------------------------------

test('no key encrypts more than one message', async () => {
  const { alice } = establish();
  const seen = new Set();

  // The same plaintext each time: identical ciphertexts would mean the key
  // and nonce had been reused, which is the failure this guards against.
  for (let i = 0; i < 100; i += 1) {
    const { payload } = encryptMessage(alice, 'identical plaintext', ALICE, BOB);
    assert.ok(!seen.has(payload), `ciphertext repeated at message ${i}`);
    seen.add(payload);
  }
});

test('a message cannot be read twice', async () => {
  const { alice, bob } = establish();
  const { payload, header } = encryptMessage(alice, 'read once', ALICE, BOB);

  assert.equal(decryptMessage(bob, payload, header, ALICE, BOB), 'read once');

  // The key has been consumed and erased, so a replayed copy is unreadable.
  assert.throws(
    () => decryptMessage(bob, payload, header, ALICE, BOB),
    /was not retained/
  );
});

// ---------------------------------------------------------------------------
// Loss and disorder
// ---------------------------------------------------------------------------

test('a lost message does not end the conversation', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'first', ALICE, BOB);
  encryptMessage(alice, 'second, lost in transit', ALICE, BOB);
  const third = encryptMessage(alice, 'third', ALICE, BOB);

  assert.equal(decryptMessage(bob, first.payload, first.header, ALICE, BOB), 'first');
  assert.equal(decryptMessage(bob, third.payload, third.header, ALICE, BOB), 'third');
  assert.equal(bob.receiveCounter, 3);
});

test('a message that arrives after the chain has passed it is still read', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);

  // The key for the position skipped over is retained, so the message is
  // readable when it arrives rather than lost.
  assert.equal(decryptMessage(bob, second.payload, second.header, ALICE, BOB), 'second');
  assert.equal(decryptMessage(bob, first.payload, first.header, ALICE, BOB), 'first');
});

test('a message claiming an implausible position is refused', async () => {
  const { alice, bob } = establish();
  const { payload, header } = encryptMessage(alice, 'ordinary message', ALICE, BOB);

  const decoded = decodeHeader(header);
  decoded.n = MAX_SKIPPED_MESSAGES + 5_000_000;
  const forged = toBase64(sodium.from_string(JSON.stringify(decoded)));

  assert.throws(
    () => decryptMessage(bob, payload, forged, ALICE, BOB),
    /refusing to advance/
  );
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

test('an altered ciphertext leaves the session untouched', async () => {
  const { alice, bob } = establish();

  const good = encryptMessage(alice, 'first', ALICE, BOB);
  const next = encryptMessage(alice, 'second', ALICE, BOB);
  const tampered = Buffer.from(next.payload, 'base64');
  tampered[tampered.length - 1] ^= 0x01;

  assert.equal(decryptMessage(bob, good.payload, good.header, ALICE, BOB), 'first');

  const chainBefore = hex(bob.receivingChainKey);
  const positionBefore = bob.receiveCounter;

  assert.throws(() =>
    decryptMessage(bob, tampered.toString('base64'), next.header, ALICE, BOB)
  );

  assert.equal(hex(bob.receivingChainKey), chainBefore);
  assert.equal(bob.receiveCounter, positionBefore);
});

test('a forged ratchet key cannot desynchronise a session', async () => {
  const { alice, bob } = establish();

  exchange(alice, bob, ALICE, BOB, 'establish the session');

  const rootBefore = hex(bob.rootKey);
  const keyBefore = hex(bob.ratchetKeyPair.publicKey);

  // A frame carrying a ratchet key the adversary generated. Were the session
  // advanced before the tag verified, this single frame would move Bob to a
  // chain Alice knows nothing about and end the conversation permanently.
  const genuine = encryptMessage(alice, 'legitimate', ALICE, BOB);
  const decoded = decodeHeader(genuine.header);
  decoded.dh = toBase64(sodium.crypto_box_keypair().publicKey);
  const forged = toBase64(sodium.from_string(JSON.stringify(decoded)));

  assert.throws(() => decryptMessage(bob, genuine.payload, forged, ALICE, BOB));

  assert.equal(hex(bob.rootKey), rootBefore);
  assert.equal(hex(bob.ratchetKeyPair.publicKey), keyBefore);

  // And the genuine message still arrives.
  assert.equal(
    decryptMessage(bob, genuine.payload, genuine.header, ALICE, BOB),
    'legitimate'
  );
});

test('altering the message number invalidates the message', async () => {
  const { alice, bob } = establish();

  encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);

  const decoded = decodeHeader(second.header);
  decoded.n = 5;
  const forged = toBase64(sodium.from_string(JSON.stringify(decoded)));

  assert.throws(() => decryptMessage(bob, second.payload, forged, ALICE, BOB));
});

test('a message re-addressed to another recipient is refused', async () => {
  const { alice, bob } = establish();
  const { payload, header } = encryptMessage(alice, 'for bob only', ALICE, BOB);

  assert.throws(() => decryptMessage(bob, payload, header, ALICE, 'someone-else'));
});