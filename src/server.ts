import express, { type Request, type Response } from 'express';
import { readFileSync } from 'fs';
import { createServer as createHttpServer, Server as HttpServer, IncomingMessage } from 'http';
import { createServer as createHttpsServer } from 'https';
import { WebSocketServer, WebSocket } from 'ws';

import {
  USERNAME_PATTERN,
  MAX_TEXT_LENGTH,
  MAX_MESSAGE_BYTES,
  MAX_ONE_TIME_PREKEYS,
  MAX_KEYS_BODY_BYTES,
  isKeyMaterial,
  type ClientMessage,
  type PublishKeysRequest,
} from './shared/protocol';
import {
  publishBundle,
  fetchBundle,
  queueMessage,
  pendingFor,
  acknowledgePending,
} from './db';

// ---------------------------------------------------------------------------
// Configuration
//
// Every security-relevant limit is declared here or in the shared protocol
// module, so that the threat model in the Final Report can reference concrete,
// auditable values rather than constants buried in the request handlers.
// ---------------------------------------------------------------------------

const PORT = Number(process.env.BURBLIT_PORT ?? 3000);
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// TLS. Disabled by default in development; see README for generating a
// self-signed certificate. The transport layer is the only thing that changes:
// no application code below depends on which server object is created.
const USE_TLS = process.env.BURBLIT_TLS === 'true';
const TLS_KEY_PATH = process.env.BURBLIT_TLS_KEY ?? 'certs/dev-key.pem';
const TLS_CERT_PATH = process.env.BURBLIT_TLS_CERT ?? 'certs/dev-cert.pem';

// Origin allowlist. Browsers always attach an Origin header to the WebSocket
// handshake, and unlike fetch() the same-origin policy does not apply to
// WebSockets: without this check any page on the internet could open a socket
// to this server using the visitor's session. See Fu and Garcia-Valls (2023).
const ALLOWED_ORIGINS = (
  process.env.BURBLIT_ALLOWED_ORIGINS ??
  `http://localhost:${PORT},http://127.0.0.1:${PORT}`
)
  .split(',')
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);

// Non-browser clients (integration tests, wscat) send no Origin header at all.
// Allowing them in development keeps the test harness simple; in production a
// missing Origin is treated as a rejected Origin.
const ALLOW_MISSING_ORIGIN = !IS_PRODUCTION;

// Rate limiting: sliding window, counted per connection.
const RATE_LIMIT_WINDOW_MS = 10_000;
const RATE_LIMIT_MAX_MESSAGES = 30;

// RFC 6455 close codes used by this server.
const CLOSE_POLICY_VIOLATION = 1008;

// ---------------------------------------------------------------------------
// Input validation
//
// The server only ever needs to understand the envelope, whose shape is
// defined once in src/shared/protocol.ts. Message content is opaque to it by
// design and will become ciphertext from day 7 onwards.
// ---------------------------------------------------------------------------

/**
 * Parses and validates an incoming frame.
 *
 * Returns the typed message, or a machine-readable reason for rejection.
 * Nothing downstream of this function touches a field that has not been
 * checked here: untrusted input is narrowed to a known shape at exactly one
 * point.
 */
function parseClientMessage(raw: string): { message: ClientMessage } | { error: string } {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    return { error: 'malformed_json' };
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return { error: 'not_an_object' };
  }

  const candidate = parsed as Record<string, unknown>;

  if (candidate.type === 'register') {
    if (typeof candidate.username !== 'string' || !USERNAME_PATTERN.test(candidate.username)) {
      return { error: 'invalid_username' };
    }
    return { message: { type: 'register', username: candidate.username } };
  }

  if (candidate.type === 'chat') {
    if (typeof candidate.to !== 'string' || !USERNAME_PATTERN.test(candidate.to)) {
      return { error: 'invalid_recipient' };
    }
    if (typeof candidate.text !== 'string' || candidate.text.length === 0) {
      return { error: 'invalid_text' };
    }
    if (candidate.text.length > MAX_TEXT_LENGTH) {
      return { error: 'text_too_long' };
    }
    if (candidate.header !== undefined) {
      if (typeof candidate.header !== 'string' || candidate.header.length > MAX_TEXT_LENGTH) {
        return { error: 'invalid_header' };
      }
    }
    return {
      message: {
        type: 'chat',
        to: candidate.to,
        text: candidate.text,
        ...(typeof candidate.header === 'string' ? { header: candidate.header } : {}),
      },
    };
  }

  return { error: 'unknown_type' };
}

/** Narrows an untrusted `POST /keys` body to the published-bundle shape. */
function parseKeysBody(body: unknown): { bundle: PublishKeysRequest } | { error: string } {
  if (typeof body !== 'object' || body === null) {
    return { error: 'not_an_object' };
  }

  const candidate = body as Record<string, unknown>;

  if (typeof candidate.username !== 'string' || !USERNAME_PATTERN.test(candidate.username)) {
    return { error: 'invalid_username' };
  }
  if (!isKeyMaterial(candidate.identityKey)) {
    return { error: 'invalid_identity_key' };
  }
  if (!isKeyMaterial(candidate.signedPrekey)) {
    return { error: 'invalid_signed_prekey' };
  }
  if (!isKeyMaterial(candidate.signedPrekeySignature)) {
    return { error: 'invalid_signature' };
  }
  if (!Array.isArray(candidate.oneTimePrekeys)) {
    return { error: 'invalid_one_time_prekeys' };
  }
  if (candidate.oneTimePrekeys.length > MAX_ONE_TIME_PREKEYS) {
    return { error: 'too_many_one_time_prekeys' };
  }
  if (!candidate.oneTimePrekeys.every(isKeyMaterial)) {
    return { error: 'invalid_one_time_prekeys' };
  }

  return {
    bundle: {
      username: candidate.username,
      identityKey: candidate.identityKey,
      signedPrekey: candidate.signedPrekey,
      signedPrekeySignature: candidate.signedPrekeySignature,
      oneTimePrekeys: candidate.oneTimePrekeys as string[],
    },
  };
}

// ---------------------------------------------------------------------------
// HTTP: the prekey registry
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: MAX_KEYS_BODY_BYTES }));
app.use(express.static('public'));

/**
 * Publishes a user's public key bundle.
 *
 * See the note on `publishBundle` in db.ts: this endpoint deliberately does
 * not authenticate the claim to a username. That residual risk is documented
 * rather than mitigated at this stage of the prototype.
 */
app.post('/keys', (req: Request, res: Response) => {
  const result = parseKeysBody(req.body);
  if ('error' in result) {
    res.status(400).json({ error: result.error });
    return;
  }

  publishBundle(result.bundle);
  console.log(
    `Published bundle for ${result.bundle.username} ` +
      `(${result.bundle.oneTimePrekeys.length} one-time prekeys)`
  );
  res.status(204).end();
});

/**
 * Fetches a bundle, consuming one one-time prekey in the process. This is the
 * step that makes an asynchronous handshake possible: the sender obtains
 * everything X3DH needs without the recipient being online.
 */
app.get('/keys/:username', (req: Request, res: Response) => {
  const username = req.params.username;
  if (typeof username !== 'string' || !USERNAME_PATTERN.test(username)) {
    res.status(400).json({ error: 'invalid_username' });
    return;
  }

  const bundle = fetchBundle(username);
  if (bundle === null) {
    res.status(404).json({ error: 'unknown_user' });
    return;
  }

  res.json(bundle);
});

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/**
 * Builds the underlying transport. Extracted so that enabling WSS is a
 * configuration change rather than a code change: the WebSocket server is
 * attached to whichever object this returns.
 */
function createTransport(): HttpServer {
  if (USE_TLS) {
    const credentials = {
      key: readFileSync(TLS_KEY_PATH),
      cert: readFileSync(TLS_CERT_PATH),
    };
    // https.Server extends http.Server, so the ws attachment is unchanged.
    return createHttpsServer(credentials, app) as unknown as HttpServer;
  }
  return createHttpServer(app);
}

const server = createTransport();

// maxPayload rejects oversized frames before they are buffered into memory,
// which closes a trivial memory-exhaustion vector.
const wss = new WebSocketServer({ server, maxPayload: MAX_MESSAGE_BYTES });

// Map of registered clients: username -> live WebSocket connection.
// The server holds connection references and routing metadata only. It never
// holds plaintext message content, and from day 7 it could not read the
// payloads it does hold.
const clients = new Map<string, WebSocket>();

function isAllowedOrigin(origin: string | undefined): boolean {
  if (origin === undefined) {
    return ALLOW_MISSING_ORIGIN;
  }
  return ALLOWED_ORIGINS.includes(origin);
}

function reject(ws: WebSocket, code: string, text: string): void {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'error', code, text }));
  }
}

/**
 * Delivers everything queued for a user who has just come online.
 *
 * A queued row is deleted only once the transport reports the frame as
 * written, so a socket that fails mid-flush leaves the remaining messages in
 * the database for the next connection rather than discarding them. The
 * converse case, a frame written but never processed by the client, would
 * require an application-level acknowledgement; that is noted as a limitation
 * rather than implemented, since it affects reliability and not secrecy.
 */
function flushQueue(ws: WebSocket, username: string): void {
  const queued = pendingFor(username);
  if (queued.length === 0) {
    return;
  }

  console.log(`Delivering ${queued.length} queued message(s) to ${username}`);

  for (const row of queued) {
    const frame = JSON.stringify({
      type: 'chat',
      from: row.sender,
      text: row.payload,
      ...(row.header !== null ? { header: row.header } : {}),
    });

    ws.send(frame, (err?: Error | null) => {
      if (err) {
        console.warn(`Failed to deliver queued message ${row.id}: ${err.message}`);
        return;
      }
      acknowledgePending(row.id);
    });
  }
}

wss.on('connection', (ws: WebSocket, request: IncomingMessage) => {
  // --- Origin check -------------------------------------------------------
  const origin = request.headers.origin;
  if (!isAllowedOrigin(origin)) {
    console.warn(`Rejected connection from disallowed origin: ${origin ?? '(none)'}`);
    reject(ws, 'origin_not_allowed', 'Origin not allowed');
    ws.close(CLOSE_POLICY_VIOLATION, 'origin_not_allowed');
    return;
  }

  // Per-connection state. Kept in the closure so it cannot leak between
  // sockets and is collected automatically when the socket is dropped.
  let username = '';
  const messageTimestamps: number[] = [];

  /**
   * Sliding-window rate limiter. Timestamps older than the window are dropped
   * on each call, so memory stays bounded by RATE_LIMIT_MAX_MESSAGES.
   */
  function exceedsRateLimit(): boolean {
    const now = Date.now();
    while (messageTimestamps.length > 0 && now - messageTimestamps[0] > RATE_LIMIT_WINDOW_MS) {
      messageTimestamps.shift();
    }
    messageTimestamps.push(now);
    return messageTimestamps.length > RATE_LIMIT_MAX_MESSAGES;
  }

  console.log(`New client connected from ${request.socket.remoteAddress ?? 'unknown'}`);

  ws.on('message', (data: Buffer) => {
    // --- Rate limiting ----------------------------------------------------
    if (exceedsRateLimit()) {
      console.warn(`Rate limit exceeded by ${username || '(unregistered)'}; closing connection`);
      reject(ws, 'rate_limit_exceeded', 'Too many messages; connection closed');
      ws.close(CLOSE_POLICY_VIOLATION, 'rate_limit_exceeded');
      return;
    }

    // --- Input validation -------------------------------------------------
    const result = parseClientMessage(data.toString());
    if ('error' in result) {
      console.warn(`Rejected message from ${username || '(unregistered)'}: ${result.error}`);
      reject(ws, result.error, 'Message rejected');
      return;
    }

    const message = result.message;

    // --- Registration -----------------------------------------------------
    if (message.type === 'register') {
      // A connection registers once. Allowing re-registration would let a
      // single socket occupy several identities.
      if (username !== '') {
        reject(ws, 'already_registered', `Already registered as ${username}`);
        return;
      }

      // Reject usernames that are already taken. Without this check the Map
      // entry is simply overwritten, so an attacker who guesses a username
      // silently becomes the recipient of every message addressed to the
      // victim. No amount of end-to-end encryption helps at that point: the
      // attacker is not breaking the ciphertext, it is being handed the
      // plaintext conversation as a legitimate endpoint.
      if (clients.has(message.username)) {
        console.warn(`Rejected duplicate registration for ${message.username}`);
        reject(ws, 'username_taken', `Username ${message.username} is already in use`);
        return;
      }

      username = message.username;
      clients.set(username, ws);
      console.log(`${username} registered`);
      ws.send(JSON.stringify({ type: 'info', text: `Registered as ${username}` }));

      flushQueue(ws, username);
      return;
    }

    // --- Relay ------------------------------------------------------------
    if (message.type === 'chat') {
      if (username === '') {
        reject(ws, 'not_registered', 'Register before sending messages');
        return;
      }

      const recipient = clients.get(message.to);

      if (recipient !== undefined && recipient.readyState === WebSocket.OPEN) {
        // The server forwards the payload untouched. `from` is set by the
        // server from the authenticated connection state, never copied from
        // the client frame, so a sender cannot forge another identity.
        recipient.send(
          JSON.stringify({
            type: 'chat',
            from: username,
            text: message.text, // Ciphertext from day 7 onwards.
            ...(message.header !== undefined ? { header: message.header } : {}),
          })
        );
        return;
      }

      // Recipient offline: queue rather than discard. This is what makes the
      // asynchronous half of X3DH usable, since a sender can complete the
      // handshake and send a first message to someone who is not connected.
      const queued = queueMessage(
        username,
        message.to,
        message.text,
        message.header ?? null
      );

      if (queued) {
        ws.send(
          JSON.stringify({
            type: 'info',
            text: `User ${message.to} is offline; message queued for delivery`,
          })
        );
      } else {
        reject(ws, 'recipient_queue_full', `Cannot queue more messages for ${message.to}`);
      }
    }
  });

  ws.on('close', () => {
    // Two guards. The empty check stops an unregistered client from deleting
    // the Map entry keyed by the empty string. The identity check stops a
    // stale or rejected socket from evicting the live session of the user who
    // currently holds that username.
    if (username !== '' && clients.get(username) === ws) {
      clients.delete(username);
      console.log(`${username} disconnected`);
    }
  });

  ws.on('error', (err: Error) => {
    console.error(`Socket error for ${username || '(unregistered)'}:`, err.message);
  });
});

server.listen(PORT, () => {
  const scheme = USE_TLS ? 'https' : 'http';
  console.log(`Burblit server listening on ${scheme}://localhost:${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
