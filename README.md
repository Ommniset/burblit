# Burblit

A web-based end-to-end encrypted messaging prototype with post-quantum considerations.

---

## Overview

Burblit is a 1-to-1 messaging prototype that implements E2EE (End-to-End Encryption). The server acts as a zero-knowledge relay — it forwards encrypted blobs between clients but never has access to plaintext message content. The project includes a clear architectural path towards a hybrid classical/post-quantum key exchange (X25519 + ML-KEM).

## Current Status

Version `v0.1-interim` — WebSocket chat skeleton with cryptographic keypair generation stub. Full E2EE implementation in progress.

---

## Stack

- **Frontend:** Vanilla TypeScript, HTML, CSS
- **Backend:** Node.js + Express + ws (WebSockets)
- **Crypto:** Web Crypto API (browser-native), libsodium (planned)
- **Database:** SQLite with better-sqlite3 (planned)

---

## Roadmap

- [x] WebSocket relay server
- [x] Frontend client
- [x] Cryptographic keypair generation stub
- [ ] Symmetric encryption (ChaCha20-Poly1305)
- [ ] Asymmetric key exchange (X25519)
- [ ] Hybrid post-quantum key exchange (X25519 + ML-KEM)
- [ ] Security testing (OWASP ZAP)

---

## How to Run

### Prerequisites
- Node.js v20 or higher
- npm

### Install dependencies

```bash
npm install
```

### Build

```bash
npm run build
```

### Start the server

```bash
npm start
```

Open your browser at **http://localhost:3000**

---

## Project Structure

```
burblit/
├── src/
│   └── server.ts        # Express + WebSocket server
├── public/
│   └── index.html       # Frontend client
├── docs/
│   ├── architecture.png # System architecture diagram
│   ├── erd.png          # Entity Relationship Diagram
│   └── sequence.png     # UML sequence diagram
├── tsconfig.json        # TypeScript configuration
└── package.json         # Project dependencies
```

---

## Out of Scope

Group messaging, multimedia exchange, mobile application, federation.
