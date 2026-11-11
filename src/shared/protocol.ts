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

// ---------------------------------------------------------------------------
// Client -> server
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
}

export type ClientMessage = RegisterMessage | ChatMessage;

// ---------------------------------------------------------------------------
// Server -> client
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
}

export type ServerMessage = InfoMessage | ErrorMessage | IncomingChatMessage;
