# Burblit

A web-based end-to-end encrypted messaging prototype with post-quantum
considerations.

Information Systems Project, BSc (Hons) Cyber Security and Networking,
NCC Education / University of Lancashire.

---

## Overview

Burblit is a one-to-one messaging prototype in which the server is a
zero-knowledge relay: it routes encrypted payloads between clients and holds
no means of reading them. All cryptography is performed in the browser, and
the relay never receives a private key, a shared secret, or a plaintext.

The key agreement is available in two forms behind a single interface. The
classical form performs a simplified X3DH over X25519. The hybrid form
additionally encapsulates a secret under ML-KEM-768 and derives the root key
from both, so that it remains secure while either the elliptic-curve or the
lattice problem is hard. Sessions are then driven by a Double Ratchet, giving
forward secrecy per message and recovery from compromise.

**Status:** `v1.0`. Implementation complete and frozen. 77 automated tests.

---

## What is implemented

| Capability | Detail |
| --- | --- |
| Key agreement | Simplified X3DH over X25519, with signed and one-time prekeys |
| Post-quantum agreement | Hybrid X25519 + ML-KEM-768 (FIPS 203), selected per conversation |
| Message encryption | ChaCha20-Poly1305, with sender, recipient and message number authenticated as associated data |
| Forward secrecy | Symmetric ratchet; one key per message, erased after use |
| Break-in recovery | Diffie-Hellman ratchet; measured to take effect after two conversational turns |
| Out-of-order delivery | Skipped message keys retained within a bounded store, across ratchet steps |
| Asynchronous messaging | Prekey registry and an offline queue; messages for a disconnected recipient are stored as ciphertext and deleted on delivery |
| Transport hardening | Origin allowlist, per-connection rate limiting, frame size limits, strict input validation |
| Browser hardening | Content Security Policy without `unsafe-inline`, `nosniff`, framing and referrer policies |

### Deliberately out of scope

Group messaging, multimedia, a mobile application, and federation. These were
excluded at the proposal stage and the exclusion has not been revisited.

---

## Known limitations

These are summarised here because a prototype that claims end-to-end
encryption without stating what it does not protect would be misleading. Each
is analysed in `report/threat-model.md`.

- **No binding between a username and an identity key.** Publication to the
  key registry is unauthenticated and replaces any existing record, so any
  party may publish key material under any name, including one already in
  use. A correspondent then verifies the bundle successfully and establishes
  a session with the publisher. This is the principal residual risk and is
  demonstrated by `scripts/probe-impersonation.js`.
- **Private keys are stored in cleartext** in IndexedDB. libsodium operates on
  raw key bytes, which precludes the non-extractable keys the Web Crypto API
  offers; the two are mutually exclusive. Script execution in the
  application's origin is therefore equivalent to full compromise.
- **The transport is not encrypted by default.** Server construction is
  factored so that enabling TLS is a configuration change, and the client
  derives its WebSocket scheme from the page origin, but neither is enabled in
  development.
- **Metadata is not protected.** The relay necessarily learns who communicates
  with whom, when, and approximately how much.
- **Downgrade to the classical agreement cannot be prevented**, only made
  visible: a signature attests to what a bundle contains and says nothing
  about what it omits. A client may be configured to require the hybrid
  agreement, in which case it refuses rather than falling back.
- **The ratchet is classical.** The hybrid agreement protects confidentiality
  for the whole session, but break-in recovery does not survive an adversary
  that combines endpoint compromise with quantum capability. Analysed in
  `report/post-quantum-analysis.md`, section 3.4.

---

## Running

### Prerequisites

Node.js 22 or later, and npm.

### Install and run

```bash
npm install
npm run build
npm start
```

Open `http://localhost:3000`. Register two users in separate tabs and send a
message between them.

A production build omits the source map and minifies the bundle:

```bash
npm run build:prod
```

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BURBLIT_PORT` | `3000` | Listening port |
| `BURBLIT_DB` | `data/burblit.db` | SQLite database path |
| `BURBLIT_ALLOWED_ORIGINS` | `http://localhost:<port>` | Comma-separated WebSocket origin allowlist |
| `BURBLIT_TLS` | `false` | Serve over HTTPS and WSS |
| `BURBLIT_TLS_KEY` | `certs/dev-key.pem` | Private key, when TLS is enabled |
| `BURBLIT_TLS_CERT` | `certs/dev-cert.pem` | Certificate, when TLS is enabled |

---

## Testing

```bash
npm test
```

77 tests across seven files, run against a real server process on a scratch
database. They cover the key schedule, both agreements, the ratchet under
loss and reordering, mode negotiation, and the zero-knowledge property of the
relay.

| File | Covers |
| --- | --- |
| `tests/zero-knowledge.test.js` | No plaintext reaches the relay, in any encoding or fragment |
| `tests/ratchet.test.js` | The key schedule's derivation properties |
| `tests/ratchet-session.test.js` | Both ratchets as two parties, including break-in recovery |
| `tests/out-of-order.test.js` | Loss and reordering within and across ratchet steps |
| `tests/mlkem.test.js` | ML-KEM-768 contract, including implicit rejection |
| `tests/hybrid.test.js` | The hybrid agreement, substituted and unsigned post-quantum keys |
| `tests/negotiation.test.js` | The mode decision table in full |

### Benchmarks

```bash
npm run bench [iterations]
```

Writes `report/benchmarks.md`. Reports median and 95th percentile after
discarding warm-up iterations.

### Adversarial probes

```bash
node scripts/probe-impersonation.js
```

Demonstrates two residual risks rather than testing a mitigation: username
takeover, and downgrade of the key agreement.

```bash
node scripts/tamper.js
```

Corrupts a queued payload so that the recipient's rejection of it can be
observed. Requires a message queued for a disconnected user.

### Inspection

```bash
npm run db:dump                    # undelivered messages, as the relay holds them
node scripts/check-prekeys.js      # registry contents per user
```

---

## Project structure

```
burblit/
├── src/
│   ├── server.ts              Express and WebSocket relay
│   ├── db.ts                  SQLite: registry and offline queue
│   ├── securityHeaders.ts     Response security headers
│   ├── shared/
│   │   ├── protocol.ts        Wire protocol and validation limits, used by both ends
│   │   └── keyAgreement.ts    The interface both agreements satisfy
│   └── client/
│       ├── main.ts            Entry point, user interface, wiring
│       ├── crypto.ts          libsodium bootstrap and encoding
│       ├── pqc.ts             ML-KEM-768, with the implementation injected
│       ├── identity.ts        Key generation, storage, publication, reconciliation
│       ├── x25519Agreement.ts Classical X3DH
│       ├── hybridAgreement.ts Hybrid X25519 + ML-KEM-768
│       ├── ratchet.ts         The Double Ratchet key schedule
│       └── session.ts         Sessions, ratchets, message protection, negotiation
├── public/                    Served assets; bundle.js and dist/ are build output
├── tests/                     Automated tests
├── scripts/                   Benchmarks, probes and inspection tools
├── report/                    Threat model, analyses, measurements, scan results
└── docs/                      Diagrams
```

---

## Report artefacts

| File | Contents |
| --- | --- |
| `report/threat-model.md` | STRIDE analysis, mitigations, nine residual risks |
| `report/post-quantum-analysis.md` | Quantum exposure, the hybrid construction, measured cost |
| `report/benchmarks.md` | Generated timings and sizes |
| `report/zap-baseline.html` | OWASP ZAP scan before remediation |
| `report/zap-after.html` | OWASP ZAP scan after remediation |

---

## Divergences from the specifications

The protocol follows X3DH and the Double Ratchet in design, with two
documented substitutions. Both specifications prescribe HKDF-SHA256, which
`libsodium-wrappers` does not expose; keyed BLAKE2b is used throughout
instead. The identity key is an Ed25519 keypair converted to X25519 where a
Diffie-Hellman is required, because libsodium does not provide XEdDSA. Neither
changes the security goal, but together they mean this is an implementation of
the same design rather than of the same protocol, and it is not wire
compatible with Signal.

Unlike PQXDH, no one-time encapsulation keys are published, so the
post-quantum contribution to the first message of a session has no forward
secrecy of its own.

---

## Licence

ISC.
