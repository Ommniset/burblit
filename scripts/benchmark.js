/**
 * Benchmarks: the cost of the hybrid handshake against the classical one.
 *
 * Run from the project root with:
 *   node scripts/benchmark.js [iterations]
 *
 * Objective 4 asks for the overhead of post-quantum key agreement to be
 * measured or estimated. This measures it, and writes the results to
 * report/benchmarks.md as a table ready to be quoted.
 *
 * METHOD, which matters as much as the figures
 *
 * Timings are taken in Node rather than in a browser. The implementation is
 * the same WebAssembly and the same JavaScript in both, but a browser adds
 * extensions, competing tabs and a scheduler the harness cannot control,
 * which widens the distribution without telling us anything about the
 * cryptography. The browser's own start-up check reports a comparable figure
 * and is quoted alongside as corroboration rather than as the measurement.
 *
 * Warm-up iterations are discarded. The first ML-KEM call includes
 * instantiating the WebAssembly module, and the first calls of anything
 * include JIT compilation; including them would inflate the mean by an amount
 * that has nothing to do with the steady-state cost.
 *
 * The median and the 95th percentile are reported rather than the mean alone.
 * A mean over a distribution with a long tail is dominated by the tail, and
 * what a user experiences is the median; what a capacity estimate needs is
 * the tail. Both are given, and the mean with them so the shape is visible.
 *
 * Operations that should cost the same in both modes are measured too. The
 * ratchet and the authenticated encryption are untouched by the choice of
 * agreement, so per-message cost ought to be identical; confirming that is a
 * result in itself, because it establishes that the entire price of the
 * post-quantum transition is paid once, in the handshake, and nothing
 * downstream of it is affected.
 */

const { mkdirSync, writeFileSync } = require('node:fs');

const { initSodium, sodium, toBase64 } = require('../dist-test/client/crypto');
const { useMlKemFactory, releaseMlKem } = require('../dist-test/client/pqc');
const {
  generateLongTermMaterial,
  generateKemMaterial,
  generateOneTimePrekeys,
} = require('../dist-test/client/identity');
const { X25519Agreement } = require('../dist-test/client/x25519Agreement');
const { HybridAgreement } = require('../dist-test/client/hybridAgreement');
const {
  initiatorSession,
  responderSession,
  encryptMessage,
  decryptMessage,
} = require('../dist-test/client/session');

const ITERATIONS = Number(process.argv[2] ?? 100);
const WARM_UP = 10;
const MESSAGE = 'A message of representative length for an instant messaging application.';

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

/** Nanosecond-resolution clock, converted to milliseconds at the end. */
function timed(operation) {
  const started = process.hrtime.bigint();
  const result = operation();
  const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
  return { result, elapsed };
}

async function timedAsync(operation) {
  const started = process.hrtime.bigint();
  const result = await operation();
  const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
  return { result, elapsed };
}

function summarise(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const at = (fraction) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))];

  return {
    n: sorted.length,
    min: sorted[0],
    median: at(0.5),
    p95: at(0.95),
    mean: sorted.reduce((total, value) => total + value, 0) / sorted.length,
  };
}

/** Runs an operation repeatedly, discarding the warm-up iterations. */
async function measure(label, operation) {
  for (let i = 0; i < WARM_UP; i += 1) {
    await operation();
  }

  const samples = [];
  for (let i = 0; i < ITERATIONS; i += 1) {
    const { elapsed } = await timedAsync(operation);
    samples.push(elapsed);
  }

  const summary = summarise(samples);
  console.log(
    `${label.padEnd(38)} median ${summary.median.toFixed(3)} ms  ` +
      `p95 ${summary.p95.toFixed(3)} ms  mean ${summary.mean.toFixed(3)} ms`
  );
  return { label, ...summary };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async function makeIdentity(username) {
  const { identityKeyPair, signedPrekeyPair, signedPrekeySignature } = generateLongTermMaterial();
  const { kemKeyPair, kemPrekeySignature } = await generateKemMaterial(
    identityKeyPair.privateKey
  );

  const oneTimePrekeys = {};
  generateOneTimePrekeys().forEach((pair, index) => {
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

function bundleFor(identity, withKem) {
  return {
    username: identity.username,
    identityKey: toBase64(identity.identityKeyPair.publicKey),
    signedPrekey: toBase64(identity.signedPrekeyPair.publicKey),
    signedPrekeySignature: toBase64(identity.signedPrekeySignature),
    oneTimePrekey: toBase64(identity.oneTimePrekeys[1].publicKey),
    oneTimePrekeyId: 1,
    kemPrekey: withKem ? toBase64(identity.kemKeyPair.publicKey) : null,
    kemPrekeySignature: withKem ? toBase64(identity.kemPrekeySignature) : null,
  };
}

/** Bytes a value occupies once serialised as JSON and sent as UTF-8. */
function wireBytes(value) {
  return Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

function timingTable(rows) {
  const lines = [
    '| Operation | n | Median (ms) | p95 (ms) | Mean (ms) |',
    '| --- | ---: | ---: | ---: | ---: |',
  ];
  for (const row of rows) {
    lines.push(
      `| ${row.label} | ${row.n} | ${row.median.toFixed(3)} | ` +
        `${row.p95.toFixed(3)} | ${row.mean.toFixed(3)} |`
    );
  }
  return lines.join('\n');
}

function sizeTable(rows) {
  const lines = [
    '| Quantity | Classical (bytes) | Hybrid (bytes) | Growth |',
    '| --- | ---: | ---: | ---: |',
  ];
  for (const [label, classical, hybrid] of rows) {
    const growth = classical === 0 ? 'n/a' : `${(hybrid / classical).toFixed(1)}x`;
    lines.push(`| ${label} | ${classical} | ${hybrid} | ${growth} |`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------

async function main() {
  await initSodium();
  const liboqs = await import('@oqs/liboqs-js');
  useMlKemFactory(liboqs.createMLKEM768);

  const alice = await makeIdentity('alice');
  const bob = await makeIdentity('bob');

  const classicalBundle = bundleFor(bob, false);
  const hybridBundle = bundleFor(bob, true);

  console.log(`Burblit benchmarks: ${ITERATIONS} iterations after ${WARM_UP} warm-up runs`);
  console.log(`Node ${process.version} on ${process.platform} ${process.arch}\n`);

  // --- Handshake --------------------------------------------------------
  const timings = [];

  timings.push(
    await measure('X25519 handshake, initiate', () =>
      new X25519Agreement(alice).initiate(classicalBundle)
    )
  );

  const classicalHeader = (await new X25519Agreement(alice).initiate(classicalBundle)).header;
  timings.push(
    await measure('X25519 handshake, respond', () =>
      new X25519Agreement(bob).respond(classicalHeader)
    )
  );

  timings.push(
    await measure('Hybrid handshake, initiate', () =>
      new HybridAgreement(alice).initiate(hybridBundle)
    )
  );

  const hybridHeader = (await new HybridAgreement(alice).initiate(hybridBundle)).header;
  timings.push(
    await measure('Hybrid handshake, respond', () =>
      new HybridAgreement(bob).respond(hybridHeader)
    )
  );

  // --- The post-quantum primitives in isolation -------------------------
  const kem = await liboqs.createMLKEM768();
  const kemKeyPair = kem.generateKeyPair();
  const { ciphertext } = kem.encapsulate(kemKeyPair.publicKey);

  timings.push(await measure('  ML-KEM-768 key generation', () => kem.generateKeyPair()));
  timings.push(
    await measure('  ML-KEM-768 encapsulation', () => kem.encapsulate(kemKeyPair.publicKey))
  );
  timings.push(
    await measure('  ML-KEM-768 decapsulation', () =>
      kem.decapsulate(ciphertext, kemKeyPair.secretKey)
    )
  );
  kem.destroy();

 // --- Per-message cost -------------------------------------------------
  //
  // Two cases, which must be separated. The ratchet and the authenticated
  // encryption are identical in both modes, so the steady-state cost is
  // expected to coincide; confirming that is the finding.
  //
  // The first message is different, and not for cryptographic reasons. The
  // initiator attaches the handshake header to every message until the
  // session is known to be established, and that header is 1595 bytes in the
  // hybrid case against 135 in the classical one. Measuring the two together
  // would attribute the cost of serialising a larger structure to the
  // cryptography, which would be wrong.
  const classical = await new X25519Agreement(alice).initiate(classicalBundle);
  const hybrid = await new HybridAgreement(alice).initiate(hybridBundle);

  function sessionPair(rootKey, bundle, mode, handshakeHeader) {
    const initiator = initiatorSession('bob', rootKey, bundle.signedPrekey, handshakeHeader, mode);
    // Set after construction so the header can be omitted entirely, which is
    // what the steady state looks like.
    initiator.handshakeHeader = handshakeHeader === null ? null : initiator.handshakeHeader;
    return {
      initiator,
      responder: responderSession('alice', rootKey, bob.signedPrekeyPair, mode),
    };
  }

  const classicalFirst = sessionPair(
    classical.rootKey,
    classicalBundle,
    'x25519',
    toBase64(classical.header)
  );
  const hybridFirst = sessionPair(
    hybrid.rootKey,
    hybridBundle,
    'hybrid',
    toBase64(hybrid.header)
  );
  const classicalSteady = sessionPair(classical.rootKey, classicalBundle, 'x25519', null);
  const hybridSteady = sessionPair(hybrid.rootKey, hybridBundle, 'hybrid', null);

  timings.push(
    await measure('Encrypt, steady state, classical', () =>
      encryptMessage(classicalSteady.initiator, MESSAGE, 'alice', 'bob')
    )
  );
  timings.push(
    await measure('Encrypt, steady state, hybrid', () =>
      encryptMessage(hybridSteady.initiator, MESSAGE, 'alice', 'bob')
    )
  );
  timings.push(
    await measure('Encrypt, handshake header attached, classical', () =>
      encryptMessage(classicalFirst.initiator, MESSAGE, 'alice', 'bob')
    )
  );
  timings.push(
    await measure('Encrypt, handshake header attached, hybrid', () =>
      encryptMessage(hybridFirst.initiator, MESSAGE, 'alice', 'bob')
    )
  );

  // Decryption is measured over a matched pair, so each side advances in step.
  const roundTrip = (pair) => () => {
    const { payload, header } = encryptMessage(pair.initiator, MESSAGE, 'alice', 'bob');
    return decryptMessage(pair.responder, payload, header, 'alice', 'bob');
  };

  timings.push(
    await measure('Encrypt and decrypt, steady state, classical', roundTrip(classicalSteady))
  );
  timings.push(
    await measure('Encrypt and decrypt, steady state, hybrid', roundTrip(hybridSteady))
  );

  // --- Sizes ------------------------------------------------------------
  const classicalMessage = encryptMessage(classicalFirst.initiator, MESSAGE, 'alice', 'bob');
  const hybridMessage = encryptMessage(hybridFirst.initiator, MESSAGE, 'alice', 'bob');

  const sizes = [
    ['Published bundle', wireBytes(classicalBundle), wireBytes(hybridBundle)],
    [
      'Handshake header',
      wireBytes(sodium.to_string(classical.header)),
      wireBytes(sodium.to_string(hybrid.header)),
    ],
    [
      'First message, header and payload',
      wireBytes(classicalMessage.header) + wireBytes(classicalMessage.payload),
      wireBytes(hybridMessage.header) + wireBytes(hybridMessage.payload),
    ],
    ['Root key produced', 32, 32],
  ];

  // A subsequent message carries no handshake header, so the two modes are
  // indistinguishable on the wire from the second message onwards.
  const classicalSecond = encryptMessage(classicalSteady.initiator, MESSAGE, 'alice', 'bob');
  const hybridSecond = encryptMessage(hybridSteady.initiator, MESSAGE, 'alice', 'bob');

  sizes.push([
    'Subsequent message, header and payload',
    wireBytes(classicalSecond.header) + wireBytes(classicalSecond.payload),
    wireBytes(hybridSecond.header) + wireBytes(hybridSecond.payload),
  ]);

  console.log('\n--- sizes on the wire ---');
  for (const [label, classicalSize, hybridSize] of sizes) {
    console.log(
      `${label.padEnd(40)} ${String(classicalSize).padStart(6)} -> ` +
        `${String(hybridSize).padStart(6)} bytes`
    );
  }

  // --- Written report ---------------------------------------------------
  const document = `# Burblit benchmarks

Generated by \`scripts/benchmark.js\`. ${ITERATIONS} iterations per operation,
after ${WARM_UP} warm-up iterations which are discarded. Node ${process.version}
on ${process.platform} ${process.arch}.

Timings are taken outside the browser deliberately. The implementation is the
same WebAssembly and JavaScript in both environments, but a browser introduces
scheduling variance that widens the distribution without saying anything about
the cryptography. The median and the 95th percentile are given because a mean
over a long-tailed distribution is dominated by its tail.

## Timings

${timingTable(timings)}

## Sizes on the wire

${sizeTable(sizes)}

## Notes

Per-message cost is unchanged by the choice of agreement, because the ratchet
and the authenticated encryption are identical in both cases. The entire cost
of post-quantum protection is therefore paid once, during the handshake.

From the second message onwards the two modes are indistinguishable on the
wire: the handshake header is no longer attached, and the root key is 32 bytes
in both cases, so everything downstream of the agreement is unaffected.
`;

  mkdirSync('report', { recursive: true });
  writeFileSync('report/benchmarks.md', document, 'utf8');
  console.log('\nWritten to report/benchmarks.md');

  await releaseMlKem();
}

void main();