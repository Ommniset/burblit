/**
 * Burblit browser client.
 *
 * All DOM nodes carrying untrusted data are built with `createElement` and
 * `textContent`. No string of remote origin is ever assigned to `innerHTML`,
 * and no inline event handler appears in the markup, so the application needs
 * no `unsafe-inline` allowance in a future Content Security Policy.
 */

import {
  USERNAME_PATTERN,
  MAX_TEXT_LENGTH,
  type ClientMessage,
  type ServerMessage,
} from '../shared/protocol';

import { initSodium, toBase64, verifyX25519Exchange } from './crypto';

// ---------------------------------------------------------------------------
// DOM access
// ---------------------------------------------------------------------------

/**
 * Resolves a required element or fails loudly at start-up.
 *
 * Under `strict` every `getElementById` is nullable. Funnelling the lookups
 * through one checked helper keeps the rest of the module free of null guards
 * and turns a renamed id into an immediate, obvious failure.
 */
function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`Missing required element: #${id}`);
  }
  return element as T;
}

const registerSection = requireElement<HTMLDivElement>('register-section');
const chatSection = requireElement<HTMLDivElement>('chat-section');
const usernameInput = requireElement<HTMLInputElement>('username-input');
const connectButton = requireElement<HTMLButtonElement>('connect-button');
const messagesPanel = requireElement<HTMLDivElement>('messages');
const recipientInput = requireElement<HTMLInputElement>('recipient-input');
const messageInput = requireElement<HTMLInputElement>('message-input');
const sendButton = requireElement<HTMLButtonElement>('send-button');

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

let socket: WebSocket | null = null;

/**
 * Derives the WebSocket endpoint from the page origin, upgrading the scheme
 * when the page itself was served over TLS. Hard-coding `ws://localhost:3000`
 * would silently downgrade the transport once WSS is enabled.
 */
function websocketUrl(): string {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${window.location.host}`;
}

function send(message: ClientMessage): void {
  if (socket === null || socket.readyState !== WebSocket.OPEN) {
    appendNotice('Not connected');
    return;
  }
  socket.send(JSON.stringify(message));
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function scrollToLatest(): void {
  messagesPanel.scrollTop = messagesPanel.scrollHeight;
}

/** Renders a server notice or a local status line. */
function appendNotice(text: string): void {
  const line = document.createElement('div');
  line.className = 'message info';
  line.textContent = text;
  messagesPanel.appendChild(line);
  scrollToLatest();
}

/**
 * Renders a chat message. The sender name and the body are inserted as text
 * nodes, so markup arriving from a peer is displayed literally rather than
 * parsed. This is the mitigation for the stored-XSS vector that the previous
 * `innerHTML` concatenation opened up.
 */
function appendChat(from: string, text: string): void {
  const line = document.createElement('div');
  line.className = 'message';

  const sender = document.createElement('strong');
  sender.textContent = `${from}: `;

  line.appendChild(sender);
  line.appendChild(document.createTextNode(text));
  messagesPanel.appendChild(line);
  scrollToLatest();
}

// ---------------------------------------------------------------------------
// Inbound handling
// ---------------------------------------------------------------------------

/**
 * Narrows a decoded frame to a known envelope. The server is not trusted to
 * send well-formed data simply because it is the server: a compromised or
 * buggy relay must not be able to drive the client into an undefined state.
 */
function parseServerMessage(raw: string): ServerMessage | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }

  const candidate = parsed as Record<string, unknown>;

  if (candidate.type === 'info' && typeof candidate.text === 'string') {
    return { type: 'info', text: candidate.text };
  }
  if (
    candidate.type === 'error' &&
    typeof candidate.code === 'string' &&
    typeof candidate.text === 'string'
  ) {
    return { type: 'error', code: candidate.code, text: candidate.text };
  }
  if (
    candidate.type === 'chat' &&
    typeof candidate.from === 'string' &&
    typeof candidate.text === 'string'
  ) {
    return { type: 'chat', from: candidate.from, text: candidate.text };
  }

  return null;
}

function handleServerMessage(message: ServerMessage): void {
  switch (message.type) {
    case 'info':
      appendNotice(message.text);
      break;
    case 'error':
      appendNotice(`Error (${message.code}): ${message.text}`);
      break;
    case 'chat':
      appendChat(message.from, message.text);
      break;
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function connect(): void {
  const username = usernameInput.value.trim();

  // Validated against the shared pattern before a frame is sent, so the user
  // gets immediate feedback rather than a round trip and a server rejection.
  if (!USERNAME_PATTERN.test(username)) {
    window.alert('Username must be 3-20 characters: letters, digits, hyphen or underscore.');
    return;
  }

  connectButton.disabled = true;
  socket = new WebSocket(websocketUrl());

  socket.addEventListener('open', () => {
    send({ type: 'register', username });
    registerSection.style.display = 'none';
    chatSection.style.display = 'block';
    messageInput.focus();
  });

  socket.addEventListener('message', (event: MessageEvent<string>) => {
    const message = parseServerMessage(event.data);
    if (message === null) {
      console.warn('Discarded malformed frame from server');
      return;
    }
    handleServerMessage(message);
  });

  socket.addEventListener('close', () => {
    appendNotice('Disconnected from server');
    socket = null;
    connectButton.disabled = false;
  });

  socket.addEventListener('error', () => {
    appendNotice('Connection error');
  });
}

function sendMessage(): void {
  const to = recipientInput.value.trim();
  const text = messageInput.value.trim();

  if (!USERNAME_PATTERN.test(to)) {
    appendNotice('Invalid recipient username');
    return;
  }
  if (text.length === 0) {
    return;
  }
  if (text.length > MAX_TEXT_LENGTH) {
    appendNotice(`Message too long (limit ${MAX_TEXT_LENGTH} characters)`);
    return;
  }

  send({ type: 'chat', to, text });
  appendChat('you', text);
  messageInput.value = '';
  messageInput.focus();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

connectButton.addEventListener('click', connect);
sendButton.addEventListener('click', sendMessage);

usernameInput.addEventListener('keydown', (event: KeyboardEvent) => {
  if (event.key === 'Enter') {
    connect();
  }
});

messageInput.addEventListener('keydown', (event: KeyboardEvent) => {
  if (event.key === 'Enter') {
    sendMessage();
  }
});

async function verifyCryptoAvailable(): Promise<void> {
  try {
    await initSodium();
    const shared = await verifyX25519Exchange();
    console.log('libsodium ready; X25519 exchange agrees. Shared secret:', toBase64(shared));
  } catch (error) {
    console.error('Cryptographic bootstrap failed:', error);
    appendNotice('Cryptography unavailable in this browser');
  }
}

void verifyCryptoAvailable();
