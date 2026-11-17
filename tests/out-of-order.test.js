/**
 * Out-of-order and delayed delivery.
 *
 * A ratchet chain advances in one direction only, so a message that arrives
 * after its position has been passed can be read only if its key was kept.
 * These tests cover the three cases that matter: disorder within one chain,
 * disorder spanning a Diffie-Hellman ratchet step, and the bound that stops
 * the store of retained keys from growing without limit.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { initSodium, sodium, toBase64 } = require('../dist-test/client/crypto');
const {
  initiatorSession,
  responderSession,
  encryptMessage,
  decryptMessage,
  MAX_STORED_KEYS,
} = require('../dist-test/client/session');

const ALICE = 'alice';
const BOB = 'bob';

function establish() {
  const rootKey = new Uint8Array(32).fill(42);
  const signedPrekeyPair = sodium.crypto_box_keypair();

  return {
    alice: initiatorSession(BOB, rootKey, toBase64(signedPrekeyPair.publicKey), 'handshake'),
    bob: responderSession(ALICE, rootKey, signedPrekeyPair),
  };
}

const read = (session, message, from, to) =>
  decryptMessage(session, message.payload, message.header, from, to);

test.before(async () => {
  await initSodium();
});

// ---------------------------------------------------------------------------
// Within one chain
// ---------------------------------------------------------------------------

test('messages delivered in reverse order are all read', async () => {
  const { alice, bob } = establish();

  const sent = [];
  for (let i = 0; i < 10; i += 1) {
    sent.push(encryptMessage(alice, `message ${i}`, ALICE, BOB));
  }

  for (let i = 9; i >= 0; i -= 1) {
    assert.equal(read(bob, sent[i], ALICE, BOB), `message ${i}`, `failed on message ${i}`);
  }
});

test('a late message is read once its predecessors have passed', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);
  const third = encryptMessage(alice, 'third', ALICE, BOB);

  // The chain advances to the third, retaining the keys it passes.
  assert.equal(read(bob, third, ALICE, BOB), 'third');

  assert.equal(read(bob, first, ALICE, BOB), 'first');
  assert.equal(read(bob, second, ALICE, BOB), 'second');
});

test('a retained key is consumed exactly once', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);

  assert.equal(read(bob, second, ALICE, BOB), 'second');
  assert.equal(read(bob, first, ALICE, BOB), 'first');

  // Retaining a key to tolerate loss must not make a message replayable.
  assert.throws(() => read(bob, first, ALICE, BOB), /was not retained/);
});

test('a retained key survives a failed authentication attempt', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);

  assert.equal(read(bob, second, ALICE, BOB), 'second');

  // An adversary replaying the first message with a corrupted body must not
  // be able to consume the key the genuine message still needs.
  const corrupted = Buffer.from(first.payload, 'base64');
  corrupted[corrupted.length - 1] ^= 0x01;

  assert.throws(() =>
    decryptMessage(bob, corrupted.toString('base64'), first.header, ALICE, BOB)
  );
  assert.equal(read(bob, first, ALICE, BOB), 'first');
});

// ---------------------------------------------------------------------------
// Across a ratchet step
// ---------------------------------------------------------------------------

test('messages from a superseded chain are read after the step', async () => {
  const { alice, bob } = establish();

  // Alice sends three; only the last reaches Bob.
  const first = encryptMessage(alice, 'first', ALICE, BOB);
  const second = encryptMessage(alice, 'second', ALICE, BOB);
  const third = encryptMessage(alice, 'third', ALICE, BOB);
  assert.equal(read(bob, third, ALICE, BOB), 'third');

  // Bob replies, so Alice ratchets and her next messages use a new chain.
  const reply = encryptMessage(bob, 'reply', BOB, ALICE);
  assert.equal(read(alice, reply, BOB, ALICE), 'reply');

  const fourth = encryptMessage(alice, 'fourth', ALICE, BOB);

  // Receiving the fourth moves Bob onto the new chain. The header records how
  // long the previous one was, so its outstanding keys are retained before
  // the old chain becomes underivable.
  assert.equal(read(bob, fourth, ALICE, BOB), 'fourth');

  assert.equal(read(bob, first, ALICE, BOB), 'first');
  assert.equal(read(bob, second, ALICE, BOB), 'second');
});

test('a long interleaved conversation loses nothing', async () => {
  const { alice, bob } = establish();
  const delayed = [];

  for (let turn = 0; turn < 10; turn += 1) {
    // Every second message from Alice is held back rather than delivered.
    const delivered = encryptMessage(alice, `alice ${turn} a`, ALICE, BOB);
    delayed.push({ message: encryptMessage(alice, `alice ${turn} b`, ALICE, BOB), turn });

    assert.equal(read(bob, delivered, ALICE, BOB), `alice ${turn} a`);

    const reply = encryptMessage(bob, `bob ${turn}`, BOB, ALICE);
    assert.equal(read(alice, reply, BOB, ALICE), `bob ${turn}`);
  }

  // Everything held back arrives at the end, out of order and spanning ten
  // ratchet steps.
  for (const { message, turn } of delayed.reverse()) {
    assert.equal(read(bob, message, ALICE, BOB), `alice ${turn} b`, `lost turn ${turn}`);
  }
});

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

test('the store of retained keys is bounded', async () => {
  const { alice, bob } = establish();

  // Deliver only every thousandth message, so each delivery retains the keys
  // for the 999 positions it passes.
  for (let batch = 0; batch < 4; batch += 1) {
    let latest;
    for (let i = 0; i < 1000; i += 1) {
      latest = encryptMessage(alice, `batch ${batch} message ${i}`, ALICE, BOB);
    }
    assert.equal(read(bob, latest, ALICE, BOB), `batch ${batch} message 999`);
  }

  assert.ok(
    bob.skippedKeys.size <= MAX_STORED_KEYS,
    `store holds ${bob.skippedKeys.size} keys, above the limit of ${MAX_STORED_KEYS}`
  );
});

test('the oldest retained keys are evicted rather than service refused', async () => {
  const { alice, bob } = establish();

  const first = encryptMessage(alice, 'the oldest message', ALICE, BOB);

  for (let batch = 0; batch < 4; batch += 1) {
    let latest;
    for (let i = 0; i < 1000; i += 1) {
      latest = encryptMessage(alice, `filler ${batch}-${i}`, ALICE, BOB);
    }
    assert.equal(read(bob, latest, ALICE, BOB), `filler ${batch}-999`);
  }

  // The earliest message has been evicted and can no longer be read, which is
  // the intended degradation. What matters is that recent messages still can.
  assert.throws(() => read(bob, first, ALICE, BOB));

  const recent = encryptMessage(alice, 'a recent message', ALICE, BOB);
  assert.equal(read(bob, recent, ALICE, BOB), 'a recent message');
});

test('a message claiming an implausible position is still refused', async () => {
  const { alice, bob } = establish();

  const genuine = encryptMessage(alice, 'ordinary message', ALICE, BOB);
  const header = JSON.parse(
    Buffer.from(genuine.header, 'base64').toString('utf8')
  );
  header.n = 5_000_000;
  const forged = Buffer.from(JSON.stringify(header), 'utf8').toString('base64');

  // Retaining skipped keys must not become a way to force unbounded work.
  assert.throws(() => decryptMessage(bob, genuine.payload, forged, ALICE, BOB), /refusing to advance/);
});