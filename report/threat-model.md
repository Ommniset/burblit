# Burblit — Threat Model

A STRIDE analysis of the prototype, with the mitigations implemented, the
risks accepted, and the adversarial testing performed against both.

## 1. Scope and method

STRIDE was chosen because it decomposes a system by the property an attack
violates — spoofing, tampering, repudiation, information disclosure, denial of
service, elevation of privilege — rather than by attack technique. A
technique-driven list tends to enumerate what the author already knows to look
for; a property-driven one forces each component to be examined against every
category, including the categories where nothing is found. The entries below
where the answer is "not applicable" or "accepted" are therefore part of the
result and not omissions from it.

The analysis covers the system as implemented. Where a mitigation exists it is
cited by the module that provides it, so a claim here can be checked against
the code rather than taken on trust. Where no mitigation exists the risk is
stated with its consequence, not merely its name.

Two things this document does not do. It does not assess the underlying
primitives: X25519, Ed25519, ChaCha20-Poly1305, BLAKE2b and ML-KEM-768 are
treated as sound, and an attack on them is outside both this analysis and the
project. And it does not cover the endpoint beyond the browser origin: a
compromised operating system, a keylogger, or a correspondent who photographs
their own screen are all outside the boundary and no protocol addresses them.

## 2. System decomposition

### 2.1 Components

| Component | Runs on | Holds |
| --- | --- | --- |
| Client | The user's browser | Identity, prekey and ratchet private keys; session state; plaintext |
| Relay | Node.js server process | Connection map; routing metadata |
| Registry | SQLite, same process | Published public keys; undelivered ciphertext |

### 2.2 Trust boundaries

1. **Browser to relay.** The network. Everything crossing it is visible to a
   passive observer and modifiable by an active one, except as the transport
   and the message encryption prevent.
2. **Relay to registry.** Within one process, but worth separating: the
   registry is what survives a restart and what an attacker with file access
   obtains.
3. **Page to browser storage.** Script executing in the application's origin
   can read everything the application stores. This boundary is the weakest
   one in the design and is examined under information disclosure.
4. **Between users.** A correspondent is not trusted to send well-formed data
   and is not prevented from retaining what they are sent.

### 2.3 Assets

| Asset | Where | Consequence of compromise |
| --- | --- | --- |
| Message plaintext | Client only | Disclosure of the conversation |
| Identity private key | Client (IndexedDB) | Impersonation of the user; decryption of future sessions |
| Signed prekey, one-time prekey private keys | Client (IndexedDB) | Decryption of handshakes that used them |
| ML-KEM secret key | Client (IndexedDB) | Loss of the post-quantum half of recorded handshakes |
| Ratchet and chain state | Client (memory) | Decryption of the current session until recovery |
| Retained skipped message keys | Client (memory) | Decryption of the specific messages they belong to |
| Routing metadata | Relay | Who communicates with whom, when, and how much |

## 3. Adversaries

| Adversary | Capability assumed |
| --- | --- |
| Passive network observer | Records all traffic indefinitely; cannot modify |
| Active network attacker | Intercepts, modifies, replays, drops; cannot break primitives |
| Malicious relay operator | Full control of the server and registry; sees all traffic |
| Malicious correspondent | A legitimate user of the system acting in bad faith |
| Local attacker | Executes script in the application's origin, or reads browser storage |
| Future quantum adversary | Records traffic now; obtains a cryptographically relevant quantum computer later |

The last of these is the reason the hybrid agreement exists. The attack does
not require the hardware to exist today, only for the recorded traffic to
remain interesting when it does.

## 4. STRIDE analysis

### 4.1 Spoofing

| # | Threat | Status |
| --- | --- | --- |
| S1 | A second connection registers an in-use username and receives messages addressed to the victim | **Mitigated.** Registration is rejected when the name is held by a live connection (`server.ts`). Before this, the map entry was overwritten and the attacker silently became the recipient |
| S2 | A sender forges the `from` field on a relayed frame | **Mitigated.** The relay sets `from` from authenticated connection state and never copies it from the frame |
| S3 | The relay substitutes its own prekey into a bundle it serves, placing itself in the middle | **Mitigated.** The signed prekey and the ML-KEM prekey are signed by the identity key and verified before use (`identity.ts`, `x25519Agreement.ts`, `hybridAgreement.ts`) |
| S4 | Any party publishes key material under any username, including one already registered, and is accepted as that user | **Accepted. See R1.** This is the principal residual risk |
| S5 | A correspondent relays a handshake while substituting identities, so that two parties believe they share a session with someone else | **Mitigated.** Both identity keys are bound into the root key derivation as associated data, so an unknown-key-share attempt produces different root keys on the two sides and the session fails |

### 4.2 Tampering

| # | Threat | Status |
| --- | --- | --- |
| T1 | Ciphertext altered in transit | **Mitigated.** ChaCha20-Poly1305 authenticates; a single altered bit causes decryption to fail outright rather than yielding corrupted output |
| T2 | Sender or recipient name rewritten so a captured message is re-addressed | **Mitigated.** Both names are authenticated as associated data, so altering either invalidates the tag |
| T3 | Message number altered to force the recipient to derive a different key or skip ahead | **Mitigated.** The message number is bound into the associated data |
| T4 | A forged ratchet key moves the recipient onto a chain its correspondent knows nothing about, ending the conversation permanently | **Mitigated.** The entire ratchet step is computed on local values and committed only after the message authenticates (`session.ts`) |
| T5 | A corrupted replay of a missing message consumes the retained key the genuine message needs | **Mitigated.** A retained key is used to decrypt before it is removed, so a failed attempt leaves it in place |
| T6 | Key material inside a published bundle altered by the relay | **Mitigated.** Signatures, as S3 |
| T7 | Post-quantum material stripped from a bundle, downgrading the session to classical | **Partially mitigated. See R5.** A signature attests to what a bundle contains, not to what it omits. A client configured to require the hybrid agreement refuses rather than falling back; one configured for automatic selection cannot detect the removal |
| T8 | Traffic modified at the transport layer | **Not mitigated in the default configuration. See R2** |

### 4.3 Repudiation

| # | Threat | Status |
| --- | --- | --- |
| R-1 | A user denies having sent a message | **By design.** X3DH provides cryptographic deniability: messages are authenticated with a shared secret rather than signed, so a recipient cannot prove authorship to a third party. This is a property of secure messaging, not a defect, and it is inherited rather than engineered |
| R-2 | The relay denies having dropped or delayed a message | **Not addressed.** The relay logs connections and deliveries for operational purposes, but those logs are under its own control and constitute no evidence to a user |

### 4.4 Information disclosure

| # | Threat | Status |
| --- | --- | --- |
| I1 | The relay reads message content | **Mitigated and verified.** The relay forwards and stores ciphertext only; verified by seven integration tests asserting that neither the encoded frame, the decoded payload, nor any eight-character fragment of the plaintext appears on the wire or in the database |
| I2 | An attacker obtaining the database file recovers past conversations | **Mitigated.** Delivered messages are deleted rather than marked, so the registry holds only messages currently in flight |
| I3 | Script injected into the page reads displayed messages or stored keys | **Partially mitigated. See R3.** The rendering path uses `textContent` exclusively and the document contains no inline script, which permits a Content Security Policy without `unsafe-inline`. The keys themselves remain readable by any script that does execute |
| I4 | The published source map discloses the application's source | **Mitigated.** Production builds emit no source map; the development build did, serving 774 KB of TypeScript to any caller |
| I5 | The relay observes who communicates with whom, when, and how often | **Accepted. See R4.** Routing requires the names, and nothing in this design conceals them |
| I6 | Recorded traffic is decrypted once a quantum computer is available | **Mitigated where the hybrid agreement is used.** The root key depends on both an elliptic-curve exchange and an ML-KEM encapsulation, and is secure while either problem is hard |
| I7 | Compromise of a session reveals earlier messages in it | **Mitigated.** Each message consumes a key derived from a one-way chain; the key and the superseded chain key are erased |
| I8 | Compromise of a device allows the conversation to be followed indefinitely | **Mitigated.** The Diffie-Hellman ratchet restores secrecy once each party has generated a ratchet key the adversary did not observe, which takes two complete turns. Measured, not asserted |
| I9 | Server response headers disclose the framework in use | **Mitigated.** `X-Powered-By` disabled |

### 4.5 Denial of service

| # | Threat | Status |
| --- | --- | --- |
| D1 | A client floods the relay with messages | **Mitigated per connection.** Sliding window of 30 messages per 10 seconds; the connection is closed on breach. **See R6** for the limits of this |
| D2 | An oversized frame exhausts memory during reassembly | **Mitigated.** Frames above 64 KiB are rejected by the WebSocket layer before buffering |
| D3 | An attacker fills the offline queue of a recipient | **Mitigated.** Per-recipient cap of 200 messages |
| D4 | A forged message claiming a large message number compels unbounded key derivation | **Mitigated.** A single message may advance a chain by at most 1000 positions |
| D5 | Messages with ever-increasing numbers force unbounded retention of skipped keys | **Mitigated.** The store holds at most 2000 keys and evicts the oldest; refusing instead would hand the adversary the outcome the bound exists to prevent |
| D6 | A forged frame desynchronises a conversation permanently | **Mitigated.** As T4 |
| D7 | The relay drops messages or refuses service | **Accepted.** Availability depends on the relay by construction; confidentiality does not |
| D8 | An attacker opens many connections, each below the per-connection limit | **Accepted. See R6** |

### 4.6 Elevation of privilege

The system has no privilege levels: every client has the same capabilities,
and the relay has no capability over message content to acquire. The category
is therefore largely empty, which is a consequence of the design rather than
an oversight. The nearest equivalent is S4, where an attacker acquires the
*identity* of another user rather than greater privilege, and it is analysed
there.

One case does belong here. The relay executes with the privileges of its
process and writes to its own database; nothing in the message path writes to
the filesystem, executes a subprocess, or assembles a SQL statement from input.
Every query is a named prepared statement, so there is no injection path from a
message or a bundle into the database engine.

## 5. Residual risks

These are accepted rather than mitigated. Each states what an attacker gains,
since a risk register that names risks without consequences cannot be used to
prioritise anything.

**R1. No binding between a username and an identity key.** Publication is
unauthenticated and replaces any existing record, so any party may publish key
material under any name, including one already in use. A correspondent
fetching that bundle verifies its signatures successfully, because the bundle
is internally consistent and signed by the publisher's own identity key, and
establishes a session with the publisher while believing it to be the named
user. The encryption performs correctly throughout; it protects the wrong
conversation. This is the most serious limitation of the prototype. Mitigating
it requires proof of possession on republication, an authenticated account
system, or trust-on-first-use pinning with out-of-band fingerprint
verification. Account authentication was excluded from scope at the proposal
stage; the other two are recorded as future work.

**R2. The transport is not encrypted in the default configuration.** Server
construction is factored so that enabling TLS is a configuration change rather
than a code change, and the client derives its WebSocket scheme from the page
origin so the socket follows the page. Neither is enabled by default in
development. Over plaintext transport an active attacker cannot read message
content, which is encrypted end to end, but can read all metadata and can
tamper with the key registry responses.

**R3. Private keys are stored in cleartext.** The Web Crypto API can hold
non-extractable keys that script cannot read, but libsodium operates on raw key
bytes and the two are mutually exclusive. Script execution in the application's
origin is therefore equivalent to full compromise of the user's conversations,
past and future. This is a structural property of performing end-to-end
encryption in a browser rather than a defect in this implementation, and it is
the reason the cross-site scripting vector in the renderer was removed before
any key material existed to steal. A native application would not face it.

**R4. Metadata is not protected.** The relay necessarily learns which users
communicate, at what times, and the approximate size of what they send. Sealed
sender, cover traffic and similar techniques exist and none is implemented.
For many realistic adversaries this is the more valuable information.

**R5. Downgrade to the classical agreement is undetectable under automatic
selection.** An active attacker able to modify registry responses can remove
the post-quantum key from a served bundle, and the client will complete a
classical handshake without anything being wrong. The available defences are
to require the hybrid agreement, in which case the client fails visibly rather
than falling back, and to report the agreement in force to the user, which the
interface does on every conversation. Neither prevents the removal; both make
it visible to a user who is looking.

**R6. Rate limiting is per connection.** An attacker opening many connections
is constrained only by the operating system. There is no global limit, no
per-address limit, and no cost imposed on opening a connection.

**R7. The post-quantum component of the first message has no forward secrecy
of its own.** Signal's PQXDH publishes one-time KEM prekeys alongside a signed
one; only the signed key is published here. An adversary who later obtained
that secret key could recover the post-quantum contribution to a recorded
handshake. The classical contribution retains its forward secrecy, and the
ratchet supersedes both after the first exchange, so the exposure is confined
to the initial message of a session.

**R8. Retained message keys weaken forward secrecy for the messages they
belong to.** Keys for positions skipped over are kept so that late messages
remain readable, which means those particular keys exist for longer than the
messages they protect. The exposure is bounded by the size of the store and is
the unavoidable price of tolerating loss.

**R9. Sessions do not survive a reload.** Session state is held in memory. The
initiator retransmits its handshake header, so a responder that reloads can
re-derive the root key, but a reloaded initiator cannot read replies already in
flight.

## 6. Adversarial testing

### 6.1 Approach

Testing was divided by what each method can establish. Automated tests assert
properties that must hold on every run and would otherwise regress silently;
an automated web scanner covers configuration and injection surfaces it can
discover; manual probing covers what neither reaches, which in this system is
mostly the protocol logic an attacker would exercise deliberately.

### 6.2 Automated

The suite comprises 77 tests. Those bearing directly on this model:

| Property | Threats | Tests |
| --- | --- | --- |
| No plaintext reaches the relay, in any encoding or fragment | I1 | 7 |
| Altered ciphertext, names or message numbers are rejected | T1, T2, T3 | 6 |
| A forged ratchet key leaves the session untouched | T4, D6 | 2 |
| A retained key survives a failed authentication attempt | T5 | 1 |
| A message cannot be read twice | I7 | 2 |
| A seized session loses the conversation after two turns | I8 | 1 |
| A substituted or unsigned post-quantum key is refused | S3, T6 | 2 |
| The hybrid policy refuses to fall back | T7 | 2 |
| Implausible message numbers are refused | D4 | 2 |
| The retained-key store is bounded and evicts | D5 | 2 |

### 6.3 Automated web scanning

OWASP ZAP, baseline and after remediation. Six alerts reduced to two, none of
high risk. Reported separately in `report/zap-baseline.html` and
`report/zap-after.html`, and discussed in the evaluation chapter. The exercise
produced one finding of its own, I4, and one methodological observation: the
spider discovers what is linked, so the key registry endpoints had to be
driven manually before they were scanned at all.

### 6.4 Manual probing

| Probe | Method | Expected | Result |
| --- | --- | --- | --- |
| Username takeover | `POST /keys` with a name already registered, using attacker-generated keys | Accepted; a correspondent then establishes a session with the attacker | Confirms R1 |
| Origin rejection | WebSocket opened from a page on another origin | Connection closed with policy violation | Confirms S1 mitigation |
| Duplicate registration | Two connections registering the same name | Second rejected | Confirms S1 mitigation |
| Unregistered send | `chat` frame before `register` | Rejected | Confirms input validation |
| Rate limit | 40 frames in rapid succession | Connection closed at the 31st | Confirms D1 |
| Oversized frame | Frame above 64 KiB | Rejected before buffering | Confirms D2 |
| Malformed input | Invalid JSON, unknown type, out-of-range fields | Rejected with a reason, connection preserved | Confirms input validation |
| Stored message inspection | Direct query of `EncryptedMessages` for an undelivered message | Ciphertext only, no column capable of holding plaintext | Confirms I1, I2 |
| Downgrade | Post-quantum key removed from a served bundle, client set to require hybrid | Refusal, with the correspondent named | Confirms R5 mitigation |

## 7. Limitations of this analysis

STRIDE is a structured prompt, not a proof. It is good at ensuring that each
component is considered against each property and poor at finding attacks that
emerge from the interaction of components none of which is individually at
fault. Two of the defects found during development were of that kind — a
duplicated call in one handler that corrupted key material held in another
process, and a per-message handshake that exhausted a finite resource — and
neither would have been surfaced by this method.

No formal verification was performed. The protocol follows X3DH and the Double
Ratchet, both of which have been formally analysed in the literature
(Cohn-Gordon et al., 2020), but this implementation diverges from them in
documented ways, and an analysis of the originals does not transfer
automatically to a variant.

The analysis was conducted by the implementer. That is the weakest methodological
point: the categories where no threat was identified are precisely the ones where
an author is least likely to see their own assumptions.
