// Probe: does @oqs/liboqs-js work at all, and what is its actual API?
//
// Run from the project root with: node scripts/probe-mlkem.js
//
// Deliberately run under Node rather than in the browser. The two questions
// "does the library work" and "does it bundle" are independent, and answering
// them separately means a failure points at one of them rather than both. If
// this succeeds and the browser does not, the problem is the bundler.
//
// The documentation shows the factory called both with and without an
// argument, so the exports are printed before anything is assumed about them.

async function main() {
  let module;
  try {
    module = await import('@oqs/liboqs-js');
  } catch (error) {
    console.error('FAIL: the package could not be imported.');
    console.error(error);
    process.exitCode = 1;
    return;
  }

  console.log('--- exports ---');
  console.log(Object.keys(module).sort().join('\n'));
  console.log('');

  if (typeof module.createMLKEM768 !== 'function') {
    console.error('FAIL: createMLKEM768 is not exported as a function.');
    process.exitCode = 1;
    return;
  }

  console.log(`createMLKEM768 declares ${module.createMLKEM768.length} parameter(s)`);

  let kem;
  try {
    kem = await module.createMLKEM768();
    console.log('createMLKEM768() succeeded with no arguments.');
  } catch (error) {
    console.error('createMLKEM768() failed with no arguments:', error.message);
    console.error('This is the signature question that decides how the WASM is loaded.');
    process.exitCode = 1;
    return;
  }

  try {
    console.log('--- algorithm info ---');
    console.log(JSON.stringify(kem.info, null, 2));
    console.log('');

    // A full encapsulation round trip. Generating a keypair alone would only
    // show that the module loaded; what the hybrid handshake depends on is
    // that two parties reach the same shared secret.
    const started = process.hrtime.bigint();

    const { publicKey, secretKey } = kem.generateKeyPair();
    const { ciphertext, sharedSecret } = kem.encapsulate(publicKey);
    const recovered = kem.decapsulate(ciphertext, secretKey);

    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    console.log('--- sizes, in bytes ---');
    console.log(`public key     ${publicKey.length}`);
    console.log(`secret key     ${secretKey.length}`);
    console.log(`ciphertext     ${ciphertext.length}`);
    console.log(`shared secret  ${sharedSecret.length}`);
    console.log('');

    const agrees =
      sharedSecret.length === recovered.length &&
      sharedSecret.every((byte, index) => byte === recovered[index]);

    if (!agrees) {
      console.error('FAIL: encapsulation and decapsulation produced different secrets.');
      process.exitCode = 1;
      return;
    }

    console.log(`OK: both parties derived the same 32-byte secret in ${elapsedMs.toFixed(2)} ms.`);
    console.log(`Shared secret: ${Buffer.from(sharedSecret).toString('base64')}`);
  } finally {
    // WASM memory is not garbage-collected, so the instance is released
    // explicitly. Forgetting this in the client would leak on every session.
    kem.destroy();
  }
}

void main();
