/**
 * Wire protocol shared by the server and the browser client.
 *
 * Both ends of the connection import this module, so the envelope definitions
 * and the validation limits exist exactly once in the codebase. A limit that
 * were declared separately on each side could drift apart silently, leaving a
 * client that accepts input the server will reject, or worse, a client that
 * refuses to send what the server would have accepted.
 *
 * Nothing in this file describes message *content*. From day 7 the `text`
 * field carries ciphertext and the server has no way to interpret it.
 */

// ---------------------------------------------------------------------------
// Validation limits
// ---------------------------------------------------------------------------

/** Usernames are routing identifiers, so the character set is deliberately narrow. */
export const USERNAME_PATTERN = /^[a-zA-Z0-9_-]{3,20}$/;

/** Maximum length of a single message payload, in UTF-16 code units. */
export const MAX_TEXT_LENGTH = 4096;

/** Maximum size of a single WebSocket frame, in bytes. Enforced by `ws`. */
export const MAX_MESSAGE_BYTES = 64 * 1024;

/** Standard base64 with optional padding. Key material travels as base64 text. */
export const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

/** Generous upper bound for any single encoded public key or signature. */
export const MAX_KEY_LENGTH = 512;

/** Size of a published one-time prekey batch. */
export const MAX_ONE_TIME_PREKEYS = 100;

/** Per-recipient cap on messages held for an offline user. */
export const MAX_PENDING_PER_RECIPIENT = 200;

/** Maximum accepted body size for the key publication endpoint. */
export const MAX_KEYS_BODY_BYTES = 128 * 1024;

// ---------------------------------------------------------------------------
// Client -> server (WebSocket)
// ---------------------------------------------------------------------------

export interface RegisterMessage {
  type: 'register';
  username: string;
}

export interface ChatMessage {
  type: 'chat';
  to: string;
  /** Plaintext today; ciphertext from day 7 onwards. */
  text: string;
  /** X3DH / ratchet header, opaque to the server. Absent until day 6. */
  header?: string;
}

export type ClientMessage = RegisterMessage | ChatMessage;

// ---------------------------------------------------------------------------
// Server -> client (WebSocket)
// ---------------------------------------------------------------------------

export interface InfoMessage {
  type: 'info';
  text: string;
}

export interface ErrorMessage {
  type: 'error';
  /** Machine-readable reason, e.g. `username_taken`, `rate_limit_exceeded`. */
  code: string;
  text: string;
}

export interface IncomingChatMessage {
  type: 'chat';
  /** Set by the server from connection state, never copied from the sender's frame. */
  from: string;
  text: string;
  header?: string;
}

export type ServerMessage = InfoMessage | ErrorMessage | IncomingChatMessage;

// ---------------------------------------------------------------------------
// Prekey registry (HTTP)
//
// Every field below is public key material. Private keys never leave the
// browser that generated them.
// ---------------------------------------------------------------------------

/** Body of `POST /keys`. All values base64-encoded. */
export interface PublishKeysRequest {
  username: string;
  identityKey: string;
  signedPrekey: string;
  /** Signature over the signed prekey, produced with the identity key. */
  signedPrekeySignature: string;
  oneTimePrekeys: string[];
}

/**
 * Response of `GET /keys/:username`.
 *
 * `oneTimePrekey` is null when the recipient's pool is exhausted. The sender
 * then performs the handshake with one fewer Diffie-Hellman, which is
 * permitted by X3DH at the cost of reduced forward secrecy for the first
 * message. `oneTimePrekeyId` tells the recipient which key to use when
 * reconstructing the shared secret.
 */
export interface PrekeyBundle {
  username: string;
  identityKey: string;
  signedPrekey: string;
  signedPrekeySignature: string;
  oneTimePrekey: string | null;
  oneTimePrekeyId: number | null;
}

/** True when `value` is a plausible base64 encoding of key material. */
export function isKeyMaterial(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_KEY_LENGTH &&
    BASE64_PATTERN.test(value)
  );
}
