/**
 * The Double Ratchet key schedule.
 *
 * These tests check the properties the ratchet's security rests on, rather
 * than fixed output values. A test asserting that a particular key equals a
 * particular constant would pin the implementation without establishing that
 * it is correct, and would have to be rewritten rather than consulted if the
 * derivation ever changed.
 *
 * The properties checked are: both parties advancing the same chain reach the
 * same keys; no two derivations collide; and a chain cannot be run backwards.
 * The last cannot be demonstrated by test, only argued from the construction,
 * so what is checked instead is the observable consequence, that successive
 * states share no structure.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { initSodium } = require('../dist-test/client/crypto');
const { advanceChain, advanceRoot, wipe, KEY_BYTES } = require('../dist-test/client/ratchet');

const SEED = new Uint8Array(KEY_BYTES).fill(7);
const OTHER_SEED = new Uint8Array(KEY_BYTES).fill(8);
const DH_OUTPUT = new Uint8Array(KEY_BYTES).fill(9);
const OTHER_DH_OUTPUT = new Uint8Array(KEY_BYTES).fill(10);

const hex = (bytes) => Buffer.from(bytes).toString('hex');

test.before(async () => {
  await initSodium();
});

// ---------------------------------------------------------------------------
// Symmetric chain
// ---------------------------------------------------------------------------

test('a chain step produces two distinct keys of the expected length', async () => {
  const step = advanceChain(SEED);

  assert.equal(step.messageKey.length, KEY_BYTES);
  assert.equal(step.nextChainKey.length, KEY_BYTES);

  // Derived from one key but under different labels, so they must differ. If
  // they did not, possession of a message key would yield the chain key and
  // every message key after it.
  assert.notEqual(hex(step.messageKey), hex(step.nextChainKey));
});

test('the chain is deterministic, so both parties reach the same keys', async () => {
  const first = advanceChain(SEED);
  const second = advanceChain(SEED);

  assert.equal(hex(first.messageKey), hex(second.messageKey));
  assert.equal(hex(first.nextChainKey), hex(second.nextChainKey));
});

test('a different chain key yields entirely different output', async () => {
  const fromSeed = advanceChain(SEED);
  const fromOther = advanceChain(OTHER_SEED);

  assert.notEqual(hex(fromSeed.messageKey), hex(fromOther.messageKey));
  assert.notEqual(hex(fromSeed.nextChainKey), hex(fromOther.nextChainKey));
});

test('every message key along a chain is unique', async () => {
  const seen = new Set();
  let chainKey = SEED;

  for (let i = 0; i < 1000; i += 1) {
    const step = advanceChain(chainKey);
    const key = hex(step.messageKey);

    assert.ok(!seen.has(key), `message key repeated at position ${i}`);
    seen.add(key);

    // A repeated chain key would make every subsequent message key repeat too.
    assert.notEqual(hex(step.nextChainKey), hex(chainKey));
    chainKey = step.nextChainKey;
  }

  assert.equal(seen.size, 1000);
});

test('two parties advancing independently stay in step', async () => {
  // The sender and the receiver never exchange chain keys: each advances its
  // own copy. The chains must track each other exactly, or the receiver will
  // derive a key the sender never used.
  let senderChain = SEED;
  let receiverChain = SEED;

  for (let i = 0; i < 50; i += 1) {
    const sent = advanceChain(senderChain);
    const received = advanceChain(receiverChain);

    assert.equal(
      hex(sent.messageKey),
      hex(received.messageKey),
      `chains diverged at message ${i}`
    );

    senderChain = sent.nextChainKey;
    receiverChain = received.nextChainKey;
  }
});

// ---------------------------------------------------------------------------
// Root chain
// ---------------------------------------------------------------------------

test('a root step produces a new root key and a chain key, both distinct', async () => {
  const step = advanceRoot(SEED, DH_OUTPUT);

  assert.equal(step.nextRootKey.length, KEY_BYTES);
  assert.equal(step.chainKey.length, KEY_BYTES);

  assert.notEqual(hex(step.nextRootKey), hex(step.chainKey));
  assert.notEqual(hex(step.nextRootKey), hex(SEED));
  assert.notEqual(hex(step.chainKey), hex(SEED));
});

test('the root step is deterministic given the same inputs', async () => {
  const first = advanceRoot(SEED, DH_OUTPUT);
  const second = advanceRoot(SEED, DH_OUTPUT);

  assert.equal(hex(first.nextRootKey), hex(second.nextRootKey));
  assert.equal(hex(first.chainKey), hex(second.chainKey));
});

test('a different Diffie-Hellman output yields a different root chain', async () => {
  // This is the property break-in recovery depends on: new entropy the
  // adversary did not observe must produce state it cannot predict.
  const withOne = advanceRoot(SEED, DH_OUTPUT);
  const withOther = advanceRoot(SEED, OTHER_DH_OUTPUT);

  assert.notEqual(hex(withOne.nextRootKey), hex(withOther.nextRootKey));
  assert.notEqual(hex(withOne.chainKey), hex(withOther.chainKey));
});

test('a different root key yields a different result for the same exchange', async () => {
  // The root key carries the history of the session, so an adversary who
  // observes a Diffie-Hellman exchange but missed an earlier step cannot
  // reconstruct the chain from the exchange alone.
  const fromSeed = advanceRoot(SEED, DH_OUTPUT);
  const fromOther = advanceRoot(OTHER_SEED, DH_OUTPUT);

  assert.notEqual(hex(fromSeed.nextRootKey), hex(fromOther.nextRootKey));
  assert.notEqual(hex(fromSeed.chainKey), hex(fromOther.chainKey));
});

test('successive root steps never repeat', async () => {
  const seen = new Set();
  let rootKey = SEED;

  for (let i = 0; i < 100; i += 1) {
    // In the real ratchet each step mixes in a fresh exchange; varying the
    // input here reproduces that.
    const dhOutput = new Uint8Array(KEY_BYTES).fill(i % 256);
    const step = advanceRoot(rootKey, dhOutput);

    assert.ok(!seen.has(hex(step.chainKey)), `chain key repeated at step ${i}`);
    seen.add(hex(step.chainKey));

    rootKey = step.nextRootKey;
  }
});

// ---------------------------------------------------------------------------
// Erasure
// ---------------------------------------------------------------------------

test('wiping a key clears the array it was held in', async () => {
  const key = advanceChain(SEED).messageKey;
  assert.ok(key.some((byte) => byte !== 0));

  wipe(key);

  assert.ok(key.every((byte) => byte === 0));
});