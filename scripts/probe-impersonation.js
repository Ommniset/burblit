/**
 * Adversarial probe: username takeover and downgrade.
 *
 * Run from the project root with:
 *   npm run build && npm run build:test && node scripts/probe-impersonation.js
 *
 * These two probes demonstrate residual risks R1 and R5 of the threat model
 * rather than testing a mitigation. They exist because a risk register that
 * asserts a consequence without demonstrating it is a claim, and because the
 * first probe's outcome is easy to understate: the encryption does not fail,
 * it succeeds against the wrong party.
 *
 * A server is started against a scratch database, so nothing here touches
 * development data.
 */

const { spawn } = require('node:child_process');
const { rmSync } = require('node:fs');

const { initSodium, toBase64 } = require('../dist-test/client/crypto');
const { useMlKemFactory } = require('../dist-test/client/pqc');
const {
  generateLongTermMaterial,
  generateKemMaterial,
  generateOneTimePrekeys,
  verifyBundle,
} = require('../dist-test/client/identity');
const { X25519Agreement } = require('../dist-test/client/x25519Agreement');
const { HybridAgreement, supportsHybrid } = require('../dist-test/client/hybridAgreement');
const { chooseMode } = require('../dist-test/client/session');

const PORT = 3200;
const BASE_URL = `http://127.0.0.1:${PORT}`;
const DB_PATH = 'data/probe.db';

let server;

function startServer() {
  return new Promise((resolve, reject) => {
    server = spawn('node', ['dist/server.js'], {
      env: { ...process.env, BURBLIT_PORT: String(PORT), BURBLIT_DB: DB_PATH },
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const timeout = setTimeout(() => reject(new Error('Server did not start')), 10_000);
    server.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('listening')) {
        clearTimeout(timeout);
        resolve();
      }
    });
    server.on('error', reject);
  });
}

async function makeIdentity(username) {
  const { identityKeyPair, signedPrekeyPair, signedPrekeySignature } = generateLongTermMaterial();
  const { kemKeyPair, kemPrekeySignature } = await generateKemMaterial(
    identityKeyPair.privateKey
  );
  const oneTimePrekeyPairs = generateOneTimePrekeys();

  return {
    username,
    identityKeyPair,
    signedPrekeyPair,
    signedPrekeySignature,
    kemKeyPair,
    kemPrekeySignature,
    oneTimePrekeyPairs,
    oneTimePrekeys: {},
  };
}

/** Publishes an identity's material under whatever name it carries. */
async function publish(identity) {
  const response = await fetch(`${BASE_URL}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: identity.username,
      identityKey: toBase64(identity.identityKeyPair.publicKey),
      signedPrekey: toBase64(identity.signedPrekeyPair.publicKey),
      signedPrekeySignature: toBase64(identity.signedPrekeySignature),
      oneTimePrekeys: identity.oneTimePrekeyPairs.map((pair) => toBase64(pair.publicKey)),
      kemPrekey: toBase64(identity.kemKeyPair.publicKey),
      kemPrekeySignature: toBase64(identity.kemPrekeySignature),
    }),
  });

  if (!response.ok) {
    throw new Error(`Publication rejected with status ${response.status}`);
  }

  const { oneTimePrekeyIds } = await response.json();
  identity.oneTimePrekeys = {};
  oneTimePrekeyIds.forEach((id, index) => {
    identity.oneTimePrekeys[id] = identity.oneTimePrekeyPairs[index];
  });
  return response.status;
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fingerprint = (identity) =>
  toBase64(identity.identityKeyPair.publicKey).slice(0, 16) + '...';

// ---------------------------------------------------------------------------

async function probeTakeover() {
  console.log('=== Probe 1: username takeover (threat model R1) ===\n');

  const victim = await makeIdentity('victim');
  const attacker = await makeIdentity('victim'); // the same name, different keys
  const correspondent = await makeIdentity('bob');

  await publish(victim);
  await publish(correspondent);
  console.log(`victim registers, publishing identity ${fingerprint(victim)}`);

  const before = await (await fetch(`${BASE_URL}/keys/victim/status`)).json();
  console.log(`registry holds        ${before.identityKey.slice(0, 16)}...`);

  // No authentication is performed, and the upsert replaces the record.
  const status = await publish(attacker);
  console.log(`\nattacker publishes under the same name: HTTP ${status}`);
  console.log(`attacker's identity   ${fingerprint(attacker)}`);

  const after = await (await fetch(`${BASE_URL}/keys/victim/status`)).json();
  console.log(`registry now holds    ${after.identityKey.slice(0, 16)}...`);
  console.log(
    `\nthe registry's record for "victim" ` +
      `${after.identityKey === before.identityKey ? 'was NOT replaced' : 'has been replaced'}`
  );

  // The correspondent now does everything correctly.
  const bundle = await (await fetch(`${BASE_URL}/keys/victim`)).json();
  const verified = await verifyBundle(bundle);
  console.log(`\nbob fetches the bundle for "victim" and verifies it: ${verified}`);
  console.log('  the bundle is internally consistent, so verification passes.');
  console.log('  it is signed by the attacker, which verification cannot detect.');

  const initiated = await new HybridAgreement(correspondent).initiate(bundle);

  const byAttacker = await new HybridAgreement(attacker).respond(initiated.header);
  console.log(`\nattacker derives the root key: ${hex(byAttacker.rootKey) === hex(initiated.rootKey)}`);

  let victimOutcome;
  try {
    const byVictim = await new HybridAgreement(victim).respond(initiated.header);
    victimOutcome = hex(byVictim.rootKey) === hex(initiated.rootKey);
  } catch {
    victimOutcome = false;
  }
  console.log(`real victim derives the root key: ${victimOutcome}`);

  console.log(
    '\nResult: the encryption performed correctly throughout. Bob holds a\n' +
      'session that nobody can read except the attacker, which is exactly what\n' +
      'was asked of it. What the system cannot establish is who is entitled to\n' +
      'the name, so it protected the wrong conversation.\n'
  );
}

async function probeDowngrade() {
  console.log('=== Probe 2: downgrade to the classical agreement (R5) ===\n');

  const peer = await makeIdentity('carol');
  const caller = await makeIdentity('dave');
  await publish(peer);
  await publish(caller);

  const genuine = await (await fetch(`${BASE_URL}/keys/carol`)).json();
  console.log(`bundle as served:      post-quantum key present: ${supportsHybrid(genuine)}`);

  // An active attacker able to modify the response removes the field. No
  // signature detects this, because a signature attests to what a bundle
  // contains and says nothing about what it omits.
  const stripped = { ...genuine, kemPrekey: null, kemPrekeySignature: null };
  console.log(`bundle after stripping: post-quantum key present: ${supportsHybrid(stripped)}`);
  console.log(`stripped bundle still verifies: ${await verifyBundle(stripped)}`);

  console.log('\nunder the automatic policy:');
  const automatic = chooseMode('auto', supportsHybrid(stripped), 'carol');
  const session = await new X25519Agreement(caller).initiate(stripped);
  console.log(`  mode selected: ${automatic}`);
  console.log(`  handshake completes: ${session.rootKey.length === 32}`);
  console.log('  nothing failed, and nothing indicated that anything was wrong.');

  console.log('\nunder the required-hybrid policy:');
  try {
    chooseMode('hybrid', supportsHybrid(stripped), 'carol');
    console.log('  mode selected: hybrid  <-- UNEXPECTED');
  } catch (error) {
    console.log(`  refused: ${error.message}`);
  }

  console.log(
    '\nResult: removal cannot be prevented. It can be made to fail visibly for\n' +
      'a user who requires post-quantum protection, and it is reported to every\n' +
      'user by the interface, which is the whole of the available defence.\n'
  );
}

async function main() {
  rmSync(DB_PATH, { force: true });
  rmSync(`${DB_PATH}-wal`, { force: true });
  rmSync(`${DB_PATH}-shm`, { force: true });

  await initSodium();
  const liboqs = await import('@oqs/liboqs-js');
  useMlKemFactory(liboqs.createMLKEM768);

  await startServer();
  try {
    await probeTakeover();
    await probeDowngrade();
  } finally {
    server?.kill();
  }
}

void main();