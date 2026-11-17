/**
 * Zero-knowledge relay: automated verification.
 *
 * Objective 2 states that the server's inability to read message content is
 * verified by code review and network traffic inspection. Inspection by hand
 * establishes it for the messages inspected; this suite establishes it for
 * every run, and will fail if a later change reintroduces plaintext onto the
 * wire.
 *
 * The tests exercise the application's own modules rather than reimplementing
 * the protocol, because a test that duplicated the cryptography would verify
 * the duplicate and not the client. The client is compiled to CommonJS by
 * tsconfig.test.json for this purpose; the browser-specific paths, IndexedDB
 * storage and relative-URL fetches, are not reached.
 *
 * A real server process is started against a scratch database, so the relay
 * under test is the one that ships.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { rmSync } = require('node:fs');
const WebSocket = require('ws');
const Database = require('better-sqlite3');

const { initSodium, toBase64, fromBase64 } = require('../dist-test/client/crypto');
const {
  generateLongTermMaterial,
  generateOneTimePrekeys,
} = require('../dist-test/client/identity');
const { X25519Agreement } = require('../dist-test/client/x25519Agreement');
const {
  initiatorSession,
  responderSession,
  encryptMessage,
  decryptMessage,
} = require('../dist-test/client/session');

const PORT = 3100;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const DB_PATH = 'data/test.db';

/**
 * A distinctive plaintext.
 *
 * Asserting that this string is absent from the relayed frame is only
 * meaningful if it could not plausibly appear by chance, so it is long and
 * unique rather than a word like "hello".
 */
const PLAINTEXT = 'canary-7f3a9c2e-the-quick-brown-fox-jumps-over-the-lazy-dog';

let server;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

function startServer() {
  return new Promise((resolve, reject) => {
    server = spawn('node', ['dist/server.js'], {
      env: { ...process.env, BURBLIT_PORT: String(PORT), BURBLIT_DB: DB_PATH },
      stdio: ['ignore', 'pipe', 'inherit'],
    });

    const timeout = setTimeout(() => reject(new Error('Server did not start in time')), 10_000);

    server.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('listening')) {
        clearTimeout(timeout);
        resolve();
      }
    });

    server.on('error', reject);
  });
}

/** Creates a user with published key material and returns its identity. */
async function createUser(name) {
  const { identityKeyPair, signedPrekeyPair, signedPrekeySignature } = generateLongTermMaterial();
  const oneTimePrekeyPairs = generateOneTimePrekeys();

  const response = await fetch(`${BASE_URL}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: name,
      identityKey: toBase64(identityKeyPair.publicKey),
      signedPrekey: toBase64(signedPrekeyPair.publicKey),
      signedPrekeySignature: toBase64(signedPrekeySignature),
      oneTimePrekeys: oneTimePrekeyPairs.map((pair) => toBase64(pair.publicKey)),
    }),
  });

  assert.equal(response.status, 200, 'key publication should succeed');
  const { oneTimePrekeyIds } = await response.json();

  const oneTimePrekeys = {};
  oneTimePrekeyIds.forEach((id, index) => {
    oneTimePrekeys[id] = oneTimePrekeyPairs[index];
  });

  return {
    username: name,
    identityKeyPair,
    signedPrekeyPair,
    signedPrekeySignature,
    oneTimePrekeys,
  };
}

/**
 * Runs the handshake and returns both sides' sessions, as the two clients
 * would hold them.
 */
async function establish(alice, bob) {
  const bundle = await (await fetch(`${BASE_URL}/keys/${bob.username}`)).json();
  const { rootKey, header } = await new X25519Agreement(alice).initiate(bundle);

  const aliceSession = initiatorSession(
    bob.username,
    rootKey,
    bundle.signedPrekey,
    toBase64(header)
  );

  const responded = await new X25519Agreement(bob).respond(header);
  const bobSession = responderSession(alice.username, responded.rootKey, bob.signedPrekeyPair);

  return { bundle, aliceSession, bobSession };
}

/** Opens a registered WebSocket connection for a user. */
function connect(username) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(`ws://127.0.0.1:${PORT}`);
    socket.on('error', reject);
    socket.on('open', () => {
      socket.send(JSON.stringify({ type: 'register', username }));
    });
    socket.on('message', function onMessage(data) {
      const frame = JSON.parse(data.toString());
      if (frame.type === 'info' && frame.text.startsWith('Registered')) {
        socket.off('message', onMessage);
        resolve(socket);
      }
    });
  });
}

/** Resolves with the next chat frame the socket receives. */
function nextChatFrame(socket) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('No chat frame received')), 5_000);
    socket.on('message', function onMessage(data) {
      const frame = JSON.parse(data.toString());
      if (frame.type === 'chat') {
        clearTimeout(timeout);
        socket.off('message', onMessage);
        resolve(frame);
      }
    });
  });
}

/** Unique names, so a run never collides with earlier data in the database. */
function uniqueName(prefix) {
  return `${prefix}${Math.floor(Math.random() * 1e6)}`;
}

// ---------------------------------------------------------------------------

test.before(async () => {
  rmSync(DB_PATH, { force: true });
  rmSync(`${DB_PATH}-wal`, { force: true });
  rmSync(`${DB_PATH}-shm`, { force: true });
  await initSodium();
  await startServer();
});

test.after(() => {
  server?.kill();
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('both parties derive an identical root key', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));

  const bundle = await (await fetch(`${BASE_URL}/keys/${bob.username}`)).json();
  const initiated = await new X25519Agreement(alice).initiate(bundle);
  const responded = await new X25519Agreement(bob).respond(initiated.header);

  assert.equal(initiated.rootKey.length, 32);
  assert.deepEqual(
    Array.from(initiated.rootKey),
    Array.from(responded.rootKey),
    'the handshake must produce the same root key on both sides'
  );
});

test('a bundle with an altered signature is refused', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));

  const bundle = await (await fetch(`${BASE_URL}/keys/${bob.username}`)).json();

  // A relay substituting its own prekey would have to forge this signature.
  const signature = fromBase64(bundle.signedPrekeySignature);
  signature[0] ^= 0xff;
  bundle.signedPrekeySignature = toBase64(signature);

  await assert.rejects(
    () => new X25519Agreement(alice).initiate(bundle),
    /signature verification/,
    'an unverifiable bundle must not be used'
  );
});

test('the frame the relay receives carries no plaintext', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));
  const { aliceSession } = await establish(alice, bob);

  const { payload, header } = encryptMessage(
    aliceSession,
    PLAINTEXT,
    alice.username,
    bob.username
  );

  const frame = JSON.stringify({ type: 'chat', to: bob.username, text: payload, header });

  // The encoded frame is what the server parses.
  assert.ok(!frame.includes(PLAINTEXT), 'the encoded frame must not contain the plaintext');

  // Decoding every base64 field must not reveal it either: an encoding is not
  // encryption, and a test that only checked the encoded form would pass for
  // a message that had merely been base64-encoded.
  const decoded =
    Buffer.from(fromBase64(payload)).toString('latin1') +
    Buffer.from(fromBase64(header)).toString('latin1');
  assert.ok(!decoded.includes(PLAINTEXT), 'the decoded payload must not contain the plaintext');

  // Nor any substantial run of it, which would indicate partial encryption.
  for (let i = 0; i + 8 <= PLAINTEXT.length; i += 1) {
    assert.ok(
      !decoded.includes(PLAINTEXT.slice(i, i + 8)),
      `the decoded payload leaked the fragment "${PLAINTEXT.slice(i, i + 8)}"`
    );
  }
});

test('the relay forwards the payload unmodified and the recipient reads it', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));

  const aliceSocket = await connect(alice.username);
  const bobSocket = await connect(bob.username);

  try {
    const { aliceSession, bobSession } = await establish(alice, bob);
    const { payload, header } = encryptMessage(
      aliceSession,
      PLAINTEXT,
      alice.username,
      bob.username
    );

    const received = nextChatFrame(bobSocket);
    aliceSocket.send(JSON.stringify({ type: 'chat', to: bob.username, text: payload, header }));

    const frame = await received;

    assert.equal(frame.text, payload, 'the relay must forward the payload byte for byte');
    assert.equal(frame.header, header, 'the relay must forward the header byte for byte');
    assert.ok(!JSON.stringify(frame).includes(PLAINTEXT));

    assert.equal(
      decryptMessage(bobSession, frame.text, frame.header, alice.username, bob.username),
      PLAINTEXT,
      'the recipient must recover the original message'
    );
  } finally {
    aliceSocket.close();
    bobSocket.close();
  }
});

test('a modified ciphertext is rejected rather than decrypted', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));
  const { aliceSession, bobSession } = await establish(alice, bob);

  const { payload, header } = encryptMessage(
    aliceSession,
    PLAINTEXT,
    alice.username,
    bob.username
  );

  const raw = fromBase64(payload);
  raw[raw.length - 1] ^= 0x01;

  assert.throws(
    () => decryptMessage(bobSession, toBase64(raw), header, alice.username, bob.username),
    'a single flipped bit must make the whole message unreadable'
  );
});

test('a message replayed towards another recipient fails to decrypt', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));
  const { aliceSession, bobSession } = await establish(alice, bob);

  const { payload, header } = encryptMessage(
    aliceSession,
    PLAINTEXT,
    alice.username,
    bob.username
  );

  // The names are authenticated as associated data, so the relay cannot
  // re-address a captured message without invalidating the tag.
  assert.throws(
    () => decryptMessage(bobSession, payload, header, alice.username, 'someone-else'),
    'altering the recipient name must invalidate the authenticator'
  );
});

test('a message queued for an offline recipient is stored as ciphertext', async () => {
  const alice = await createUser(uniqueName('alice'));
  const bob = await createUser(uniqueName('bob'));

  const aliceSocket = await connect(alice.username);

  try {
    const { aliceSession } = await establish(alice, bob);
    const { payload, header } = encryptMessage(
      aliceSession,
      PLAINTEXT,
      alice.username,
      bob.username
    );

    aliceSocket.send(JSON.stringify({ type: 'chat', to: bob.username, text: payload, header }));

    // Allow the relay to persist the row.
    await new Promise((resolve) => setTimeout(resolve, 300));

    const db = new Database(DB_PATH, { readonly: true });
    const rows = db
      .prepare('SELECT payload, header FROM EncryptedMessages WHERE recipient = ?')
      .all(bob.username);
    db.close();

    assert.equal(rows.length, 1, 'the message should have been queued');
    assert.ok(
      !rows[0].payload.includes(PLAINTEXT),
      'the stored payload must not contain the plaintext'
    );
    assert.ok(
      !Buffer.from(fromBase64(rows[0].payload)).toString('latin1').includes(PLAINTEXT),
      'the decoded stored payload must not contain the plaintext'
    );
  } finally {
    aliceSocket.close();
  }
});