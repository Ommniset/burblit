// Copies the liboqs-js runtime modules into the directory the server serves.
//
// Run from the project root with: node scripts/copy-pqc.js
// It is part of the client build, not a manual step.
//
// The package loads each algorithm on demand with a dynamic import, so its
// modules are resolved by the browser at run time rather than bundled. They
// therefore have to be reachable from the page. Serving them from public/
// keeps every request same-origin, which is what the interim report's
// content-delivery-network problem was about, and the on-demand loading means
// only ML-KEM is ever fetched rather than the whole algorithm catalogue.

const { cpSync, existsSync, readdirSync, statSync } = require('node:fs');
const { join } = require('node:path');

const PACKAGE_ROOT = join('node_modules', '@oqs', 'liboqs-js');
const SOURCE = join(PACKAGE_ROOT, 'dist');
const DESTINATION = join('public', 'dist');

if (!existsSync(SOURCE)) {
  console.error(`Expected the package's modules at ${SOURCE}, which does not exist.`);
  if (existsSync(PACKAGE_ROOT)) {
    console.error('The package contains:');
    for (const entry of readdirSync(PACKAGE_ROOT)) {
      console.error(`  ${entry}`);
    }
  } else {
    console.error('The package is not installed. Run: npm install @oqs/liboqs-js');
  }
  process.exit(1);
}

cpSync(SOURCE, DESTINATION, { recursive: true });

let files = 0;
let bytes = 0;
for (const entry of readdirSync(DESTINATION, { recursive: true })) {
  const full = join(DESTINATION, entry);
  if (statSync(full).isFile()) {
    files += 1;
    bytes += statSync(full).size;
  }
}

console.log(
  `Copied ${files} file(s), ${(bytes / 1024 / 1024).toFixed(1)} MB, ` +
    `to ${DESTINATION}. Only the modules actually imported are fetched by the browser.`
);