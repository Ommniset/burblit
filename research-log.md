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

## Entry 3 — 10/05/2026

### Source
Unger, N., Dechand, S., Bonneau, J., Fahl, S., Perl, H., Goldberg, I.
and Smith, M. (2015) 'SoK: Secure Messaging', *2015 IEEE Symposium
on Security and Privacy*. IEEE, pp. 232–249.
Available at: https://ieeexplore.ieee.org/document/7163029
(Accessed: 10 May 2026).

### Key Takeaways

**1. Three core challenges of secure messaging**
The paper identifies three fundamental challenges that any secure
messaging system must address: trust establishment (how users verify
they are talking to the right person), conversation security (protecting
message content in transit and at rest), and transport privacy (hiding
metadata such as who is communicating with whom and when).

**2. Legacy protocols dominate despite their insecurity**
The vast majority of electronic communication still runs over protocols
like SMTP and SMS that were never designed with end-to-end security
in mind. This creates a systemic gap between the security properties
users expect and what the underlying infrastructure actually provides.

**3. Structured framework for comparing messaging systems**
The paper provides a formal taxonomy of security properties against
which existing systems — including Signal, TextSecure, WhatsApp,
and Wire — can be evaluated. This framework is directly useful for
justifying Burblit's design decisions in the Interim Report background
section.

### Relevance to Burblit
This paper provides the academic foundation for the comparative
analysis of E2EE systems in Appendix A of the Interim Report.
The three-challenge framework (trust, conversation security, transport
privacy) maps directly onto Burblit's threat model and justifies the
choice of E2EE over simpler transport-layer approaches.

---

## Entry 4 — 10/05/2026

### Source
Fu, Y. and García-Valls, M. (2023) 'Security aspects of full-duplex
web interactions and WebSockets', *2023 20th ACS/IEEE International
Conference on Computer Systems and Applications (AICCSA)*. IEEE.
DOI: 10.1109/AICCSA59173.2023.10479302
(Accessed: 10 May 2026).

### Key Takeaways

**1. WebSockets introduce specific vulnerabilities that require
explicit mitigation**
Unlike HTTP, WebSockets do not enforce the Same-Origin Policy and
have no built-in authentication during the handshake. This creates
attack surfaces including DoS, cross-site WebSocket hijacking,
man-in-the-middle attacks, SQL injection, and cache poisoning.
Security must be added explicitly by the developer — it is not
provided by the protocol itself.

**2. WSS (WebSocket Secure) is the baseline mandatory requirement**
The paper identifies WSS — WebSockets over TLS/SSL — as the
most critical mitigation. It encrypts the transport channel and
makes man-in-the-middle attacks infeasible. For Burblit, this means
all WebSocket connections must use WSS in any non-local deployment.

**3. Defence-in-depth: multiple mitigations are required in combination**
No single measure is sufficient. The paper recommends layering:
WSS for transport encryption, Origin header validation, ticket-based
authentication for the handshake, input validation on both client and
server sides, and rate limiting to mitigate DoS. Relying solely on
the Origin header for authentication is explicitly flagged as
insufficient.

### Relevance to Burblit
This paper directly informs Burblit's non-functional security
requirements (NFR1-NFR3). The vulnerability catalogue maps onto
Burblit's threat model: the server must use WSS, validate input,
and implement rate limiting. These will be documented as concrete
mitigations in section 2.1 of the Interim Report.

---

## Entry 5 — 11/05/2026

### SMART Objectives (refined from Initial Proposal feedback)

The following objectives replace the vague objectives from the Initial
Proposal. Each objective is Specific, Measurable, Achievable, Relevant,
and Time-bound, addressing the tutor feedback that objectives should
"define success criteria".

**Objective 1 — Real-time communication**
Implement a WebSocket server using Node.js and the `ws` library that
supports a minimum of two simultaneous client connections, verified
by a functional demonstration of bidirectional message exchange
between two browser tabs, to be completed by 20/05/2026.

**Objective 2 — End-to-end encryption**
Implement E2EE using libsodium-wrappers, with X25519 for key exchange
and ChaCha20-Poly1305 for message encryption, such that the server
never has access to plaintext message content at any point, verified
by code review and network traffic inspection, to be completed by
31/08/2026.

**Objective 3 — Formal design artefacts**
Produce a minimum of three formal design diagrams — a system
architecture diagram, an ERD, and a UML sequence diagram of the
X3DH handshake flow — to be completed by 14/05/2026.

**Objective 4 — Post-quantum evaluation**
Produce a documented comparative analysis of a hybrid X25519 + ML-KEM
approach versus the classical X25519-only approach, including measured
or estimated bandwidth overhead figures, to be completed by
01/11/2026.

---
