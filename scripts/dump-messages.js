// Shows everything the relay is holding for undelivered messages.
//
// Run from the project root with: node scripts/dump-messages.js
//
// The point of this view is what is absent from it. The server stores routing
// metadata and an opaque payload; there is no column in which a plaintext
// could appear, and no key with which the stored payload could be read.

const Database = require('better-sqlite3');

const db = new Database('data/burblit.db', { readonly: true });

const rows = db
  .prepare(
    `SELECT id, sender, recipient, payload, header, created_at
     FROM EncryptedMessages
     ORDER BY id ASC`
  )
  .all();

if (rows.length === 0) {
  console.log('EncryptedMessages is empty: every queued message has been delivered.');
  process.exit(0);
}

console.log(`EncryptedMessages holds ${rows.length} undelivered message(s).\n`);

for (const row of rows) {
  console.log(`id        ${row.id}`);
  console.log(`from      ${row.sender}`);
  console.log(`to        ${row.recipient}`);
  console.log(`queued    ${new Date(row.created_at).toISOString()}`);
  console.log(`payload   ${row.payload}`);
  console.log(`header    ${row.header ?? '(none)'}`);
  console.log('');
}

db.close();