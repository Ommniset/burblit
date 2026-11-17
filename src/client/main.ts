/**
 * Burblit browser client.
 *
 * All DOM nodes carrying untrusted data are built with `createElement` and
 * `textContent`. No string of remote origin is ever assigned to `innerHTML`,
 * and no inline event handler appears in the markup, so the application needs
 * no `unsafe-inline` allowance in a future Content Security Policy.
 */

import { createMLKEM768 } from '@oqs/liboqs-js';

import {
  USERNAME_PATTERN,
  MAX_TEXT_LENGTH,
  type ClientMessage,
  type ServerMessage,
} from '../shared/protocol';
import { initSodium, toBase64, verifyX25519Exchange } from './crypto';
import { loadOrCreateIdentity, clearIdentity, type Identity } from './identity';
import { useMlKemFactory, verifyMlKemExchange } from './pqc';
import {
  sessionAsInitiator,
  sessionAsResponder,
  existingSession,
  encryptMessage,
  decryptMessage,
  handshakeHeaderFrom,
  setModePolicy,
  clearSessions,
  type ModePolicy,
  type Session,
} from './session';

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
const resetButton = requireElement<HTMLButtonElement>('reset-button');
const messagesPanel = requireElement<HTMLDivElement>('messages');
const recipientInput = requireElement<HTMLInputElement>('recipient-input');
const messageInput = requireElement<HTMLInputElement>('message-input');
const sendButton = requireElement<HTMLButtonElement>('send-button');
const modeSelect = requireElement<HTMLSelectElement>('mode-select');

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

let socket: WebSocket | null = null;
let connecting = false;

/**
 * This client's long-term key material, loaded at connection time.
 *
 * Held at module scope because both halves of the handshake need it: the
 * initiator performs Diffie-Hellman with its identity key, and the responder
 * looks up the one-time prekey the initiator consumed.
 */
let identity: Identity | null = null;

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
// Reporting the agreement in force
// ---------------------------------------------------------------------------

/** Peers whose session mode has already been reported. */
const announced = new Set<string>();

/**
 * States which agreement protects a conversation, once per correspondent.
 *
 * A security property the user cannot observe is not a property the user has.
 * The distinction matters most in the case this is designed to surface: a
 * conversation that silently fell back to the classical agreement looks
 * exactly like one that did not.
 */
function announce(session: Session): void {
  if (announced.has(session.peer)) {
    return;
  }
  announced.add(session.peer);

  appendNotice(
    session.agreementMode === 'hybrid'
      ? `Session with ${session.peer}: hybrid X25519 + ML-KEM-768`
      : `Session with ${session.peer}: classical X25519 only`
  );
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
    return {
      type: 'chat',
      from: candidate.from,
      text: candidate.text,
      ...(typeof candidate.header === 'string' ? { header: candidate.header } : {}),
    };
  }

  return null;
}

/**
 * Establishes or recovers the session for an incoming message, then decrypts.
 *
 * A message carrying a handshake header can always be read, because the
 * header is sufficient to re-derive the root key. One that does not requires
 * a session already in memory, and a reload destroys those: the failure is
 * reported rather than hidden, since silently dropping a message the user's
 * correspondent believes was delivered would be worse than saying so.
 */
async function receive(from: string, payload: string, header?: string): Promise<void> {
  if (identity === null) {
    return;
  }
  if (header === undefined) {
    appendNotice(`Discarded a message from ${from} that carried no header`);
    return;
  }

  try {
    const handshake = handshakeHeaderFrom(header);
    const session =
      handshake !== null
        ? await sessionAsResponder(identity, from, handshake)
        : existingSession(from);

    if (session === null) {
      appendNotice(`Cannot read a message from ${from}: no session established`);
      return;
    }

    announce(session);
    appendChat(from, decryptMessage(session, payload, header, from, identity.username));
  } catch (error) {
    // Reached when authentication fails, and also when a correspondent opens
    // a classical session while this client requires the hybrid agreement.
    console.error('Could not read message:', error);
    appendNotice(`Message from ${from} was discarded: ${String(error)}`);
  }
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
      void receive(message.from, message.text, message.header);
      break;
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

async function connect(): Promise<void> {
  // The button is disabled on entry, but the Enter shortcut bypasses that, so
  // re-entry is guarded explicitly rather than through the control's state.
  // Concurrent entry matters here because publication is destructive: two
  // overlapping runs would each replace the other's prekey batch.
  if (connecting || socket !== null) {
    return;
  }
  connecting = true;

  const username = usernameInput.value.trim();

  // Validated against the shared pattern before a frame is sent, so the user
  // gets immediate feedback rather than a round trip and a server rejection.
  if (!USERNAME_PATTERN.test(username)) {
    window.alert('Username must be 3-20 characters: letters, digits, hyphen or underscore.');
    connecting = false;
    return;
  }

  connectButton.disabled = true;

  // Key material must exist and be published before registering, so that a
  // correspondent who fetches this user's bundle immediately afterwards finds
  // something to fetch.
  try {
    identity = await loadOrCreateIdentity(username);
  } catch (error) {
    console.error('Identity setup failed:', error);
    window.alert('Could not set up key material. See the console for details.');
    connectButton.disabled = false;
    connecting = false;
    return;
  }

  console.log(
    `Identity ready for ${username}.`,
    `Fingerprint: ${toBase64(identity.identityKeyPair.publicKey).slice(0, 16)}...`,
    `One-time prekeys held: ${Object.keys(identity.oneTimePrekeys).length}`
  );

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
    connecting = false;
    connectButton.disabled = false;
  });

  socket.addEventListener('error', () => {
    appendNotice('Connection error');
  });
}

async function sendMessage(): Promise<void> {
  const to = recipientInput.value.trim();
  const text = messageInput.value.trim();

  if (!USERNAME_PATTERN.test(to)) {
    appendNotice('Invalid recipient username');
    return;
  }
  if (text.length === 0) {
    return;
  }
  // The plaintext bound is enforced here because the client is the only party
  // that can see a plaintext; the server bounds the encoded payload instead.
  if (text.length > MAX_TEXT_LENGTH) {
    appendNotice(`Message too long (limit ${MAX_TEXT_LENGTH} characters)`);
    return;
  }
  if (identity === null) {
    appendNotice('No key material loaded');
    return;
  }

  try {
    // An existing session is reused whichever role this party holds in it. A
    // handshake is run only when none exists, since each one consumes a
    // one-time prekey from the recipient's finite published batch.
    const session = existingSession(to) ?? (await sessionAsInitiator(identity, to));
    announce(session);

    const { payload, header } = encryptMessage(session, text, identity.username, to);
    send({ type: 'chat', to, text: payload, header });
  } catch (error) {
    // Reached when the recipient has published no key material, and also when
    // the policy requires the hybrid agreement and they cannot provide it.
    console.error('Could not send message:', error);
    appendNotice(`Could not send to ${to}: ${String(error)}`);
    return;
  }

  appendChat('you', text);
  messageInput.value = '';
  messageInput.focus();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

connectButton.addEventListener('click', () => void connect());
sendButton.addEventListener('click', () => void sendMessage());

usernameInput.addEventListener('keydown', (event: KeyboardEvent) => {
  if (event.key === 'Enter') {
    void connect();
  }
});

messageInput.addEventListener('keydown', (event: KeyboardEvent) => {
  if (event.key === 'Enter') {
    void sendMessage();
  }
});

/**
 * Changing the policy discards every established session.
 *
 * A session already derived under one agreement is not retroactively covered
 * by another, so leaving it in place would leave the interface reporting a
 * protection that the conversation does not have. Discarding forces a fresh
 * handshake under the new policy, which costs one of the correspondent's
 * one-time prekeys and is the honest outcome.
 */
modeSelect.addEventListener('change', () => {
  const policy = modeSelect.value as ModePolicy;
  setModePolicy(policy);
  clearSessions();
  announced.clear();
  appendNotice(`Key agreement policy set to "${policy}"; existing sessions discarded`);
});

/**
 * Development aid: discards local key material and every session derived from
 * it, then closes the connection.
 *
 * Closing matters. Leaving the socket open would keep this client operating
 * with keys held only in memory, which no longer exist in storage and whose
 * public halves the registry may have replaced, producing failures that look
 * like protocol defects rather than a deliberate reset.
 */
resetButton.addEventListener('click', () => {
  const username = usernameInput.value.trim();
  if (!USERNAME_PATTERN.test(username)) {
    window.alert('Enter the username whose keys should be discarded.');
    return;
  }
  void clearIdentity(username).then(() => {
    clearSessions();
    announced.clear();
    identity = null;
    socket?.close();
    window.alert(`Discarded local keys for ${username}. Reload before reconnecting.`);
  });
});

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

/**
 * Confirms that both primitives work in this browser before any conversation
 * depends on them.
 *
 * Each check performs a complete exchange rather than merely generating a key,
 * because initialising successfully and agreeing on a secret are different
 * claims, and only the second is the one the handshake rests on.
 */
async function verifyCryptoAvailable(): Promise<void> {
  // The application's entry point is where the concrete implementation is
  // chosen; the module that uses it depends only on the capability.
  useMlKemFactory(createMLKEM768);

  try {
    await initSodium();
    const shared = await verifyX25519Exchange();
    console.log('libsodium ready; X25519 exchange agrees. Shared secret:', toBase64(shared));

    const mlkem = await verifyMlKemExchange();
    console.log(
      `ML-KEM-768 ready; encapsulation agrees in ${mlkem.elapsedMs.toFixed(2)} ms.`,
      `Shared secret: ${toBase64(mlkem.sharedSecret)}`
    );
  } catch (error) {
    console.error('Cryptographic bootstrap failed:', error);
    appendNotice('Cryptography unavailable in this browser');
  }
}

void verifyCryptoAvailable();
