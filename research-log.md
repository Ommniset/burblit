# Burblit — Research Log

**Student:** Adam Ben Ahmed Belachi  
**Student ID:** 2233282  
**Project:** Burblit ISP — E2EE Messaging Prototype  

---

## Entry 1 — 09/05/2026

### Source
Marlinspike, M. and Perrin, T. (2016) *The X3DH Key Agreement Protocol*.
Signal. Available at: https://signal.org/docs/specifications/x3dh/
(Accessed: 9 May 2026).

### Key Takeaways

**1. Purpose and security properties**
X3DH establishes a shared secret key between two parties who mutually
authenticate each other based on public keys. It provides two critical
security properties: forward secrecy (past messages remain secure if
keys are later compromised) and cryptographic deniability (messages
cannot be proven to originate from a specific sender).

**2. Three-party architecture**
The protocol involves three roles: a sender, a recipient, and a server.
The server acts as a passive intermediary that stores public key material
but never has access to the shared secret. This is directly relevant to
Burblit's design, where the server must relay data without being able
to read it.

**3. Three-phase flow**
X3DH operates in three phases: (1) the recipient publishes their identity
key and prekeys to the server; (2) the sender fetches a prekey bundle
from the server and uses it to derive the shared secret and send an
initial message; (3) the recipient processes the initial message and
derives the same shared secret independently. This asymmetric flow
allows messaging even when the recipient is offline.

### Relevance to Burblit
X3DH will be the key agreement mechanism for Burblit's initial handshake
between users. The three-phase flow maps directly onto Burblit's
architecture: users register prekeys on the server, and senders derive
shared secrets without the server ever learning them.

---

## Entry 2 — 09/05/2026

### Source
Perrin, T. and Marlinspike, M. (2016) *The Double Ratchet Algorithm*.
Signal. Available at: https://signal.org/docs/specifications/doubleratchet/
(Accessed: 9 May 2026).

### Key Takeaways

**1. Per-message key derivation**
The Double Ratchet derives a new encryption key for every single message.
Crucially, earlier keys cannot be calculated from later ones, and later
keys cannot be calculated from earlier ones. This gives the protocol
both forward secrecy and break-in recovery — two properties that are
essential for a trustworthy messaging system.

**2. KDF chain properties**
The protocol relies on a KDF (Key Derivation Function) chain with three
formal properties: resilience (output keys appear random even if the
adversary controls inputs), forward security (past keys appear random
after compromise), and break-in recovery (future keys appear random
after compromise, provided future inputs add entropy). Together these
properties ensure that a single key compromise does not cascade into
a full session compromise.

**3. Post-quantum limitation and path forward**
The Double Ratchet as specified does not provide security against
quantum computers. However, the paper notes that a post-quantum
variant can be constructed using any post-quantum Key Encapsulation
Mechanism (KEM), such as ML-KEM. The main practical challenge is
bandwidth: post-quantum KEMs produce keys orders of magnitude larger
than elliptic curve keys, which can be impractical for
bandwidth-limited applications.

### Relevance to Burblit
The Double Ratchet will govern per-message encryption in Burblit once
X3DH establishes the initial shared secret. The post-quantum limitation
noted in the paper directly informs Burblit's design decision to
evaluate a hybrid X25519 + ML-KEM approach in the Final Report phase
(August 2026), with bandwidth overhead as a key evaluation criterion.

---
