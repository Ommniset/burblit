/**
 * Persistence layer.
 *
 * The server stores exactly two categories of data: public key material, which
 * is public by definition, and undelivered message payloads, which are opaque
 * to it. It never stores a private key, a shared secret or a plaintext
 * message, and there is no code path by which it could: the relevant values
 * are never transmitted to it in the first place.
 *
 * Undelivered payloads are removed on delivery rather than retained. Keeping
 * them would leave a growing archive of ciphertext on the relay, which an
 * adversary with future access to the database file could exfiltrate wholesale
 * in the hope of later cryptanalysis. Deleting on delivery means a compromise
 * of the server yields only the small set of messages currently in flight.
 */

import Database from 'better-sqlite3';
import { mkdirSync } from 'fs';
import { dirname } from 'path';

import {
  MAX_PENDING_PER_RECIPIENT,
  type PrekeyBundle,
  type PublishKeysRequest,
} from './shared/protocol';

const DB_PATH = process.env.BURBLIT_DB ?? 'data/burblit.db';

if (DB_PATH !== ':memory:') {
  mkdirSync(dirname(DB_PATH), { recursive: true });
}

const db = new Database(DB_PATH);

// WAL improves concurrent read performance and is the recommended mode for
// better-sqlite3. Foreign keys are off by default in SQLite and must be
// enabled per connection.
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS Users (
    username      TEXT    PRIMARY KEY,
    identity_key  TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS Prekeys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL REFERENCES Users(username) ON DELETE CASCADE,
    key_type   TEXT    NOT NULL CHECK (key_type IN ('signed', 'one_time')),
    public_key TEXT    NOT NULL,
    signature  TEXT,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS EncryptedMessages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sender     TEXT    NOT NULL,
    recipient  TEXT    NOT NULL,
    payload    TEXT    NOT NULL,
    header     TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_prekeys_lookup
    ON Prekeys(username, key_type, used);

  CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON EncryptedMessages(recipient, id);
`);

/**
 * Adds a column to an existing table if it is absent.
 *
 * The post-quantum key material was introduced after the schema had already
 * been created, and a database that predates it would otherwise have to be
 * discarded. Recreating it is cheap in development and unacceptable in
 * principle, and the nullable column it produces is useful in its own right:
 * a user registered before the upgrade has no post-quantum key, which is
 * exactly how a client discovers that a correspondent cannot perform a hybrid
 * handshake.
 *
 * The table and column names are literals in this file, never user input.
 */
function ensureColumn(table: string, column: string, definition: string): void {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!columns.some((existing) => existing.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    console.log(`Schema: added ${table}.${column}`);
  }
}

ensureColumn('Users', 'kem_public_key', 'TEXT');
ensureColumn('Users', 'kem_signature', 'TEXT');

// ---------------------------------------------------------------------------
// Prepared statements
//
// better-sqlite3 is synchronous, so statements are prepared once at module
// load and reused. This also means every query in the codebase is a named,
// parameterised statement: no SQL string is ever assembled from user input.
// ---------------------------------------------------------------------------

const upsertUser = db.prepare(`
  INSERT INTO Users (username, identity_key, kem_public_key, kem_signature, created_at)
  VALUES (@username, @identityKey, @kemPrekey, @kemPrekeySignature, @createdAt)
  ON CONFLICT(username) DO UPDATE SET
    identity_key   = excluded.identity_key,
    kem_public_key = excluded.kem_public_key,
    kem_signature  = excluded.kem_signature
`);

const deletePrekeysFor = db.prepare(`DELETE FROM Prekeys WHERE username = ?`);

const insertPrekey = db.prepare(`
  INSERT INTO Prekeys (username, key_type, public_key, signature, used, created_at)
  VALUES (@username, @keyType, @publicKey, @signature, 0, @createdAt)
`);

const selectUser = db.prepare(`
  SELECT identity_key, kem_public_key, kem_signature FROM Users WHERE username = ?
`);

const selectSignedPrekey = db.prepare(`
  SELECT public_key, signature FROM Prekeys
  WHERE username = ? AND key_type = 'signed'
  ORDER BY id DESC LIMIT 1
`);

const selectUnusedOneTimePrekey = db.prepare(`
  SELECT id, public_key FROM Prekeys
  WHERE username = ? AND key_type = 'one_time' AND used = 0
  ORDER BY id ASC LIMIT 1
`);

const selectUnusedPrekeyIds = db.prepare(`
  SELECT id FROM Prekeys
  WHERE username = ? AND key_type = 'one_time' AND used = 0
  ORDER BY id ASC
`);

const markPrekeyUsed = db.prepare(`UPDATE Prekeys SET used = 1 WHERE id = ?`);

const countPending = db.prepare(`
  SELECT COUNT(*) AS total FROM EncryptedMessages WHERE recipient = ?
`);

const insertPending = db.prepare(`
  INSERT INTO EncryptedMessages (sender, recipient, payload, header, created_at)
  VALUES (@sender, @recipient, @payload, @header, @createdAt)
`);

const selectPending = db.prepare(`
  SELECT id, sender, payload, header FROM EncryptedMessages
  WHERE recipient = ? ORDER BY id ASC
`);

const deletePending = db.prepare(`DELETE FROM EncryptedMessages WHERE id = ?`);

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

interface UserRow {
  identity_key: string;
  kem_public_key: string | null;
  kem_signature: string | null;
}

interface SignedPrekeyRow {
  public_key: string;
  signature: string | null;
}

interface OneTimePrekeyRow {
  id: number;
  public_key: string;
}

interface CountRow {
  total: number;
}

export interface PendingRow {
  id: number;
  sender: string;
  payload: string;
  header: string | null;
}

// ---------------------------------------------------------------------------
// Prekey registry
// ---------------------------------------------------------------------------

/**
 * Stores a user's public key material, replacing any previous bundle.
 *
 * KNOWN LIMITATION, documented rather than mitigated. Publication is
 * unauthenticated, and the upsert replaces an existing record, so any party
 * may publish key material under any username, including one already
 * registered. A correspondent who then fetches that bundle verifies its
 * signatures successfully, because the bundle is internally consistent and
 * signed by the publisher's own identity key, and establishes a session with
 * the publisher while believing it to be the named user. The signatures
 * prevent the relay from altering key material inside a bundle; they cannot
 * establish who is entitled to a name. Binding the two requires proof of
 * possession on republication, an out-of-band channel, or trust-on-first-use
 * pinning in the client, none of which is in scope. This is the principal
 * residual risk in the threat model.
 */
export const publishBundle = db.transaction((bundle: PublishKeysRequest): number[] => {
  const createdAt = Date.now();

  upsertUser.run({
    username: bundle.username,
    identityKey: bundle.identityKey,
    kemPrekey: bundle.kemPrekey,
    kemPrekeySignature: bundle.kemPrekeySignature,
    createdAt,
  });

  // Republishing replaces the whole set. Keeping stale one-time prekeys would
  // let a sender encrypt to a key the recipient has already discarded.
  deletePrekeysFor.run(bundle.username);

  insertPrekey.run({
    username: bundle.username,
    keyType: 'signed',
    publicKey: bundle.signedPrekey,
    signature: bundle.signedPrekeySignature,
    createdAt,
  });

  const oneTimePrekeyIds: number[] = [];
  for (const publicKey of bundle.oneTimePrekeys) {
    const info = insertPrekey.run({
      username: bundle.username,
      keyType: 'one_time',
      publicKey,
      signature: null,
      createdAt,
    });
    oneTimePrekeyIds.push(Number(info.lastInsertRowid));
  }

  return oneTimePrekeyIds;
});

/**
 * Fetches a bundle and consumes one one-time prekey.
 *
 * Selection and consumption run in a single transaction so that two senders
 * fetching concurrently cannot be handed the same one-time prekey, which would
 * silently cost the second sender the forward secrecy that key was there to
 * provide.
 *
 * Returning `oneTimePrekey: null` when the pool is exhausted is deliberate and
 * matches the X3DH specification: the handshake proceeds with one fewer
 * Diffie-Hellman, at the cost of reduced forward secrecy for the initial
 * message. Refusing to serve a bundle instead would turn an exhausted pool
 * into a denial of service.
 *
 * `kemPrekey` is null for a user whose client does not publish post-quantum
 * material. That is not an error either: it is how a sender discovers that a
 * hybrid handshake is not available with this correspondent.
 */
export const fetchBundle = db.transaction((username: string): PrekeyBundle | null => {
  const user = selectUser.get(username) as UserRow | undefined;
  if (user === undefined) {
    return null;
  }

  const signed = selectSignedPrekey.get(username) as SignedPrekeyRow | undefined;
  if (signed === undefined || signed.signature === null) {
    return null;
  }

  const oneTime = selectUnusedOneTimePrekey.get(username) as OneTimePrekeyRow | undefined;
  if (oneTime !== undefined) {
    markPrekeyUsed.run(oneTime.id);
  }

  return {
    username,
    identityKey: user.identity_key,
    signedPrekey: signed.public_key,
    signedPrekeySignature: signed.signature,
    oneTimePrekey: oneTime?.public_key ?? null,
    oneTimePrekeyId: oneTime?.id ?? null,
    kemPrekey: user.kem_public_key,
    kemPrekeySignature: user.kem_signature,
  };
});

/**
 * Reports what the registry holds for a user, consuming nothing.
 *
 * Exists separately from bundle retrieval because a client must be able to
 * check its stored material against the registry on every connection, and
 * checking by fetching a bundle would spend a one-time prekey each time.
 */
export function registryStatus(
  username: string
): { identityKey: string; kemPrekey: string | null; availablePrekeyIds: number[] } | null {
  const row = selectUser.get(username) as UserRow | undefined;
  if (row === undefined) {
    return null;
  }
  const ids = (selectUnusedPrekeyIds.all(username) as { id: number }[]).map((r) => r.id);
  return {
    identityKey: row.identity_key,
    kemPrekey: row.kem_public_key,
    availablePrekeyIds: ids,
  };
}

// ---------------------------------------------------------------------------
// Offline message queue
// ---------------------------------------------------------------------------

/**
 * Queues a message for a recipient who is not currently connected.
 *
 * Returns false when the recipient's queue is full. The cap bounds the storage
 * an unauthenticated sender can force the server to allocate, which would
 * otherwise be an unbounded disk-exhaustion vector surviving across restarts.
 */
export function queueMessage(
  sender: string,
  recipient: string,
  payload: string,
  header: string | null
): boolean {
  const { total } = countPending.get(recipient) as CountRow;
  if (total >= MAX_PENDING_PER_RECIPIENT) {
    return false;
  }

  insertPending.run({
    sender,
    recipient,
    payload,
    header,
    createdAt: Date.now(),
  });
  return true;
}

export function pendingFor(recipient: string): PendingRow[] {
  return selectPending.all(recipient) as PendingRow[];
}

/** Called only after the transport confirms the frame was written. */
export function acknowledgePending(id: number): void {
  deletePending.run(id);
}

export function closeDatabase(): void {
  db.close();
}
