# Burblit

A web-based end-to-end encrypted messaging prototype with post-quantum considerations.

**Student:** Adam Ben Ahmed Belachi  
**Student ID:** 2233282  
**Module:** Information Systems Project — Spring 2026  
**University:** NCC Education / University of Lancashire  

---

## Project Status

Current version: `v0.1-interim` — WebSocket chat skeleton with cryptographic keypair generation stub.

---

## Stack

- **Frontend:** Vanilla TypeScript, HTML, CSS
- **Backend:** Node.js + Express + ws (WebSockets)
- **Crypto:** Web Crypto API (browser-native)
- **Database:** SQLite with better-sqlite3 (planned)

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
├── research-log.md      # Annotated research entries
├── tsconfig.json        # TypeScript configuration
└── package.json         # Project dependencies
```
---

## Out of Scope

Group messaging, multimedia exchange, mobile application, federation.
