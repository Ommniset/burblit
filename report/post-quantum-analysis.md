# Burblit — Post-Quantum Security Analysis

An assessment of what a quantum adversary would and would not be able to do
against this system, what the hybrid agreement changes, what it costs, and
what it leaves unaddressed.

## 1. The threat, and why it is present tense

A quantum computer of sufficient scale breaks the hard problems that
asymmetric cryptography is built on. Shor's algorithm (Shor, 1997) solves
integer factorisation and the discrete logarithm in polynomial time, which
ends RSA, finite-field Diffie-Hellman and elliptic-curve Diffie-Hellman
together. No such machine is known to exist, and estimates of when one might
vary by decades.

That uncertainty is often taken to mean the problem is a future one. For
confidentiality it is not, and the reason is simple enough to state in a
sentence: an adversary can record encrypted traffic today and decrypt it when
the capability arrives. The property at risk is not the secrecy of a message
now but its secrecy over its useful lifetime, and that lifetime is a property
of the message rather than of the adversary. A conversation that must stay
private for twenty years needs protection against the machines of twenty
years' time, which means protection applied when it is sent. The attack is
usually called *harvest now, decrypt later*, and it requires nothing of the
adversary today except storage.

For a messaging system this is the relevant framing. The cost of being wrong
about the timeline is asymmetric: deploying post-quantum protection early and
finding it was unnecessary wastes bandwidth, while deploying it late and
finding it was necessary cannot be corrected retrospectively for anything
already sent.

## 2. What is actually at risk in this system

It is worth being precise about which components a quantum adversary affects,
because the answer is narrower than "the encryption".

### 2.1 The symmetric layer is largely unaffected

Message content is encrypted with ChaCha20-Poly1305 under 256-bit keys, and
every derivation uses BLAKE2b with 256-bit outputs. Grover's algorithm
(Grover, 1996) gives a quadratic speedup on unstructured search, which halves
the effective security of a symmetric key: a 256-bit key offers roughly
128 bits against a quantum adversary. That remains far beyond reach, and the
speedup does not parallelise well, which erodes it further in practice.

No change to the symmetric layer is therefore required, and none was made.
This is the usual conclusion in the literature and it is worth stating
explicitly, because a reader who has absorbed the general alarm about quantum
computing may reasonably assume everything needs replacing.

### 2.2 The key agreement is the whole of the exposure

What a quantum adversary breaks is the establishment of the shared secret.
Every X25519 exchange in the classical handshake is computable from the public
values the adversary has recorded, which means the root key is computable, and
from the root key everything else follows. The Ed25519 signatures on the
published prekeys are equally broken, which additionally permits forgery of
key material rather than merely recovery of it.

The practical consequence is that a recorded conversation protected only by
the classical agreement is recoverable in full once the capability exists, no
matter how strong the symmetric layer is. The asymmetric layer is the
bottleneck, and it is the only part of this system that the hybrid agreement
changes.

## 3. The hybrid construction

### 3.1 Why hybrid rather than post-quantum alone

ML-KEM is standardised (NIST, 2024) and believed secure against both classical
and quantum adversaries, so an obvious question is why the classical exchange
is retained at all.

The answer is an asymmetry of maturity. X25519 has two decades of analysis
behind it and one known weakness, which is precisely the one under discussion.
Lattice-based constructions are comparatively young, and the recent history of
post-quantum candidates contains a cautionary example: SIKE reached the fourth
round of the NIST process before an attack recovered its private keys in
minutes on a single core (Castryck and Decru, 2023). ML-KEM rests on different
assumptions and has received far more scrutiny, but the episode establishes
that late breaks in this field are not hypothetical.

Combining the two means the root key is secure while *either* problem remains
hard. Deploying ML-KEM alone would exchange a known, dated weakness for an
unknown one; deploying X25519 alone accepts the known weakness in full. The
hybrid accepts neither, at a cost measured in section 4. Guizani et al. (2026)
reach the same conclusion for the transition period generally.

### 3.2 Why ML-KEM-768

ML-KEM is standardised at three parameter sets, and the choice is not
arbitrary.

| Parameter set | NIST category | Public key | Ciphertext |
| --- | --- | --- | --- |
| ML-KEM-512 | 1 | 800 B | 768 B |
| **ML-KEM-768** | **3** | **1184 B** | **1088 B** |
| ML-KEM-1024 | 5 | 1568 B | 1568 B |

ML-KEM-512 was rejected on a specific ground rather than general caution. In a
hybrid construction the sensible target is for the post-quantum component to
be no weaker than the classical one it reinforces, since otherwise it becomes
the limiting factor and the combination is weaker than it appears. Category 1
is the level of a 128-bit block cipher search; pairing it with X25519 would
mean the post-quantum half constrains the result. ML-KEM-1024 was rejected on
cost: it is a further 384 bytes of public key and 480 of ciphertext for
protection beyond what this threat model asks for. ML-KEM-768 at category 3 is
the general-purpose recommendation and is what Signal selected for PQXDH
(Kret and Schmidt, 2023).

### 3.3 Why the two primitives cannot simply be substituted

X25519 is a key agreement: both parties publish a value, and each combines its
own private half with the other's public half to reach the same secret. ML-KEM
is a key encapsulation mechanism, and is asymmetric in a way the former is not.
One party publishes a public key; the other generates a secret, encapsulates it
under that key, and transmits the resulting ciphertext; the holder of the
secret key decapsulates and recovers the same value. There is no operation
corresponding to combining two encapsulation keys.

This shapes the implementation rather than merely describing it. The hybrid
handshake carries both exchanges in full, and the additional traffic is
almost entirely the 1088-byte ciphertext, which must travel with the first
message. It also means the responder must have published an encapsulation key
in advance, which is why the registry schema required extension and why a
correspondent without one cannot participate in a hybrid handshake at all.

### 3.4 Where the protection applies, and where it stops

This is the point at which a careless analysis overstates its conclusion, so
it is worth working through.

The hybrid agreement protects the *initial* root key. Everything after it is
driven by the Double Ratchet, whose Diffie-Hellman ratchet uses X25519 — which
a quantum adversary can compute. The obvious inference is that the protection
is undone at the first ratchet step, and that inference is wrong, for a reason
worth stating.

Each root step derives the next root key from the current one and the new
Diffie-Hellman output together. The adversary can compute the Diffie-Hellman
output, having recorded both public keys, but the derivation is keyed by the
current root key, which it does not have. The unknown value is carried forward
at every step, so the entire chain remains unknown to an adversary that never
learned the initial root key. Confidentiality of the whole conversation
therefore rests on the hybrid agreement, and harvest-now-decrypt-later is
addressed for the session as a whole rather than for its first message only.

What is *not* preserved is break-in recovery against that adversary. The
purpose of the Diffie-Hellman ratchet is that an attacker who obtains the
session state at some moment loses the conversation once each party has
contributed entropy the attacker did not observe. Against a quantum adversary
that entropy is not unobserved: every subsequent X25519 output is computable
from the recorded traffic. An adversary who compromises a device *and* can
break X25519 therefore follows the conversation indefinitely, where a purely
classical adversary would be locked out after two turns, as measured in the
evaluation.

The accurate statement is therefore narrower than "the system is
post-quantum". Confidentiality against a recording adversary is protected;
recovery from endpoint compromise, against an adversary who also has quantum
capability, is not. Addressing the second requires a post-quantum ratchet,
which Signal has since pursued and which is beyond the scope of this
prototype. It is recorded in future work rather than elided.

## 4. Measured cost

Figures from `report/benchmarks.md`: 100 iterations after 10 discarded warm-up
runs, median reported.

| Operation | Classical | Hybrid | Difference |
| --- | ---: | ---: | ---: |
| Handshake, initiating party | 0.772 ms | 0.936 ms | +0.164 ms (1.21x) |
| Handshake, responding party | 0.475 ms | 0.556 ms | +0.081 ms (1.17x) |
| Message encryption, steady state | 0.015 ms | 0.015 ms | none |
| Encrypt and decrypt, steady state | 0.025 ms | 0.024 ms | none |

| Quantity on the wire | Classical | Hybrid | Growth |
| --- | ---: | ---: | ---: |
| Published bundle | 382 B | 2046 B | 5.4x |
| Handshake header | 135 B | 1595 B | 11.8x |
| First message, total | 472 B | 3068 B | 6.5x |
| Subsequent message, total | 220 B | 220 B | 1.0x |
| Root key produced | 32 B | 32 B | 1.0x |

Two findings follow, and the first was contrary to expectation.

**The computational cost is small.** The hybrid handshake is 1.21 times the
classical one, not the order of magnitude anticipated. ML-KEM-768 performs key
generation, encapsulation and decapsulation in roughly 0.05 milliseconds each,
which is less than a single one of the four Diffie-Hellman exchanges that X3DH
already performs. Lattice operations are arithmetically simple compared with
elliptic-curve scalar multiplication, and the intuition that post-quantum
cryptography is computationally expensive does not survive measurement here.

**The cost is bandwidth, and it is paid once.** The published bundle grows by a
factor of 5.4 and the first message by 6.5, an increase of 2596 bytes.
Thereafter the two modes are byte-for-byte identical on the wire, because the
handshake header is no longer attached and the root key is the same 32 bytes
in both cases. Amortised across a conversation of a hundred messages the
overhead is approximately 26 bytes per message; across ten messages it is 260.

The practical implication is that the transition is cheap for sustained
conversations and comparatively expensive for systems that establish many
short-lived sessions. For a messaging application, where sessions persist, it
is close to free.

## 5. Limitations

**No one-time encapsulation keys.** Signal's PQXDH publishes one-time KEM
prekeys alongside a signed one. Only the signed key is published here, so the
post-quantum contribution to the initial message has no forward secrecy of its
own: an adversary later obtaining that secret key could recover it from a
recorded handshake. The classical contribution retains its forward secrecy,
and the ratchet supersedes both after the first exchange, so the exposure is
confined to the initial message of a session.

**The ratchet remains classical**, as analysed in 3.4.

**Decapsulation failures are silent.** ML-KEM performs implicit rejection: a
corrupted ciphertext or a mismatched key yields a deterministic but unrelated
value rather than an error, which denies an adversary the oracle that a
distinguishable failure would supply. The design consequence is that the
handshake cannot learn from decapsulation whether an exchange was tampered
with; the two parties simply derive different root keys and the discrepancy
surfaces when the first message fails to authenticate. This is correct
behaviour, but it does mean that a tampering attempt is reported to the user
as an authentication failure rather than as a key agreement failure.

**Downgrade cannot be prevented.** An active attacker able to modify registry
responses can remove the published encapsulation key, and no signature detects
this, because a signature attests to what a bundle contains and says nothing
about what it omits. The defences available are to fail visibly when the
hybrid agreement is required, and to report the agreement in force to the
user. Both are implemented; neither prevents the removal.

**The implementation is not wire-compatible with Signal.** HKDF-SHA256 is
specified by both X3DH and PQXDH; libsodium does not expose it, and keyed
BLAKE2b is used throughout instead. The substitution preserves the property
required of the derivation, but it means this is an implementation of the same
design rather than of the same protocol.

**A policy cost was incurred by the choice of library.** The implementation is
WebAssembly, and browsers treat instantiating a WASM module as code generation
under a Content Security Policy, so `wasm-unsafe-eval` is required for it to
run at all. Selecting liboqs therefore costs a slightly weaker policy than a
pure-JavaScript implementation would have required. The token permits
WebAssembly compilation but not evaluation of JavaScript, so the exposure is
bounded, but the trade-off is real and is not usually mentioned in discussions
of post-quantum deployment.

## 6. Conclusion

The exposure of this system to a quantum adversary is confined to its key
agreement; the symmetric layer requires no change and received none. The
hybrid construction removes that exposure for confidentiality, including for
the conversation beyond its first message, because the unknown initial root
key is carried forward through every subsequent ratchet step. It does not
restore break-in recovery against an adversary that combines endpoint
compromise with quantum capability, which would require a post-quantum ratchet.

The measured cost is lower than the design discussion anticipated and falls
almost entirely on bandwidth rather than computation: a 1.21x handshake and
2596 additional bytes once per conversation, after which the two modes are
indistinguishable. On these figures the argument for deploying a hybrid
agreement in a messaging application does not rest on predictions about when
quantum computers will arrive. It rests on the observation that the cost of
protecting against them is already small enough that the prediction need not
be made.

## References cited in this chapter

- Castryck, W. and Decru, T. (2023) 'An Efficient Key Recovery Attack on SIDH',
  *Advances in Cryptology – EUROCRYPT 2023*. Springer, pp. 423–447.
- Grover, L.K. (1996) 'A fast quantum mechanical algorithm for database
  search', *Proceedings of the Twenty-Eighth Annual ACM Symposium on Theory of
  Computing*. ACM, pp. 212–219.
- Guizani, S. et al. (2026) — as listed in the main bibliography.
- Kret, E. and Schmidt, R. (2023) *The PQXDH Key Agreement Protocol*. Signal.
- Murray, H., O'Mahony, G. and Mjeda, A. (2025) 'Quantum Computing and
  Post-Quantum Cryptography: Preparing for the Next Era of Cybersecurity',
  *DSN-S*. IEEE, pp. 176–177.
- NIST (2024) *FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
  Standard*. National Institute of Standards and Technology.
- Shor, P.W. (1997) 'Polynomial-Time Algorithms for Prime Factorization and
  Discrete Logarithms on a Quantum Computer', *SIAM Journal on Computing*,
  26(5), pp. 1484–1509.
