// Diagnostic: what the registry currently holds for each user.
// Run from the project root with: node scripts/check-prekeys.js

const Database = require('better-sqlite3');

const db = new Database('data/burblit.db', { readonly: true });

const users = db.prepare('SELECT username, identity_key FROM Users').all();

if (users.length === 0) {
  console.log('No users registered.');
  process.exit(0);
}

for (const user of users) {
  const rows = db
    .prepare(
      `SELECT key_type AS type,
              MIN(id)  AS lowest,
              MAX(id)  AS highest,
              COUNT(*) AS total,
              SUM(used) AS consumed
       FROM Prekeys
       WHERE username = ?
       GROUP BY key_type`
    )
    .all(user.username);

  console.log(`\n${user.username}  identity ${user.identity_key.slice(0, 16)}...`);
  for (const row of rows) {
    console.log(
      `  ${row.type.padEnd(9)} ids ${row.lowest}-${row.highest}  ` +
        `count ${row.total}  consumed ${row.consumed}`
    );
  }

  const next = db
    .prepare(
      `SELECT id FROM Prekeys
       WHERE username = ? AND key_type = 'one_time' AND used = 0
       ORDER BY id ASC LIMIT 1`
    )
    .get(user.username);

  console.log(`  next one-time prekey to be served: ${next ? next.id : '(none left)'}`);
}

db.close();