// Test harness: corrupts every queued message so that the recipient's
// authenticator can be shown to reject it.
//
// Run from the project root with: node scripts/tamper.js
//
// One character of the encoded payload is changed, at an offset inside the
// ciphertext rather than the nonce prefix, so that the modification exercises
// Poly1305 rather than simply producing a wrong nonce.

const Database = require('better-sqlite3');

const OFFSET = 24;

const db = new Database('data/burblit.db');
const rows = db.prepare('SELECT id, sender, recipient, payload FROM EncryptedMessages').all();

if (rows.length === 0) {
  console.log('No queued messages. Send one to a disconnected user first.');
  process.exit(0);
}

const update = db.prepare('UPDATE EncryptedMessages SET payload = ? WHERE id = ?');

for (const row of rows) {
  if (row.payload.length <= OFFSET) {
    console.log(`Message ${row.id} is too short to corrupt; skipped.`);
    continue;
  }

  const replacement = row.payload[OFFSET] === 'A' ? 'B' : 'A';
  const corrupted =
    row.payload.slice(0, OFFSET) + replacement + row.payload.slice(OFFSET + 1);

  update.run(corrupted, row.id);
  console.log(`Corrupted message ${row.id} (${row.sender} -> ${row.recipient}).`);
}

db.close();