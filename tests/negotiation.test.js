/**
 * Mode negotiation.
 *
 * The rule deciding which agreement a handshake uses is a pure function of the
 * configured policy and of what the correspondent has published, so it can be
 * checked exhaustively here without a registry or a network. That matters
 * because the rule is where a downgrade would happen if one were permitted,
 * and a security property that holds only in the cases someone remembered to
 * try by hand is not one worth claiming.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  chooseMode,
  setModePolicy,
  getModePolicy,
  handshakeMode,
} = require('../dist-test/client/session');
const { initSodium, sodium, toBase64 } = require('../dist-test/client/crypto');

test.before(async () => {
  await initSodium();
});

// ---------------------------------------------------------------------------
// The decision table, in full
// ---------------------------------------------------------------------------

test('auto takes the hybrid agreement when it is available', () => {
  assert.equal(chooseMode('auto', true, 'bob'), 'hybrid');
});

test('auto falls back to the classical agreement when it is not', () => {
  // A correspondent running an older client is reachable rather than
  // unreachable; refusing here would make post-quantum support a barrier to
  // communication rather than an improvement to it.
  assert.equal(chooseMode('auto', false, 'bob'), 'x25519');
});

test('the classical policy ignores availability', () => {
  // Used to run a conversation classically for comparison, which is what
  // makes the measurement of the hybrid's cost empirical.
  assert.equal(chooseMode('x25519', true, 'bob'), 'x25519');
  assert.equal(chooseMode('x25519', false, 'bob'), 'x25519');
});

test('the hybrid policy proceeds when the material is published', () => {
  assert.equal(chooseMode('hybrid', true, 'bob'), 'hybrid');
});

test('the hybrid policy refuses to fall back', () => {
  // The downgrade this prevents: an active relay can strip the post-quantum
  // key from a bundle it serves, and no signature detects that, because a
  // signature covers what a bundle contains and not what it omits. Failing
  // visibly is the only available defence.
  assert.throws(
    () => chooseMode('hybrid', false, 'bob'),
    /refusing to fall back/,
    'a client requiring post-quantum protection must not silently accept less'
  );
});

test('the error names the correspondent', () => {
  // The user has to be able to act on it, which means knowing who could not
  // be reached under the policy they chose.
  assert.throws(() => chooseMode('hybrid', false, 'carol'), /carol/);
});

// ---------------------------------------------------------------------------
// Policy state
// ---------------------------------------------------------------------------

test('the policy defaults to auto and can be changed', () => {
  assert.equal(getModePolicy(), 'auto');

  setModePolicy('hybrid');
  assert.equal(getModePolicy(), 'hybrid');

  setModePolicy('auto');
  assert.equal(getModePolicy(), 'auto');
});

// ---------------------------------------------------------------------------
// Reading the mode a correspondent chose
// ---------------------------------------------------------------------------

function encodeHandshake(object) {
  return toBase64(sodium.from_string(JSON.stringify(object)));
}

test('the mode is read from the handshake header', () => {
  assert.equal(handshakeMode(encodeHandshake({ v: 1, mode: 'x25519' })), 'x25519');
  assert.equal(handshakeMode(encodeHandshake({ v: 1, mode: 'hybrid' })), 'hybrid');
});

test('an unknown mode is an error rather than a default', () => {
  // Treating an unrecognised value as classical would be a downgrade the
  // recipient performed on itself, which is the one case no relay would even
  // have to work for.
  assert.throws(
    () => handshakeMode(encodeHandshake({ v: 1, mode: 'something-else' })),
    /unknown agreement/
  );
  assert.throws(() => handshakeMode(encodeHandshake({ v: 1 })), /unknown agreement/);
});

test('a malformed handshake header is rejected', () => {
  assert.throws(() => handshakeMode('not base64 at all!!'), /not valid encoded JSON/);
  assert.throws(() => handshakeMode(toBase64(sodium.from_string('{'))), /not valid encoded JSON/);
});