# KEM-MAKE Protocol Messages

DER-encoded message structures for the KEM-MAKE key-establishment protocol
(https://applied-paranoia.com/assets/2026/kem-make.pdf), built on
[asn1crypto](https://pypi.org/project/asn1crypto/).

## Layout

```
kem-make/
├── pyproject.toml             # packaging metadata AND all dependencies (src layout)
├── src/kem_make/
│   ├── bottom.py              # message structures (the "bottom" layer) -- authoritative
│   ├── crypto_backend.py      # runtime capability check for the crypto backend
│   ├── keystore.py            # encrypted on-disk key directory (public + private keys)
│   ├── session.py             # the session layer: handshake + established traffic, one cid
│   ├── candidate.py           # bounded tracking of unauthenticated first-flight candidates
│   ├── dispatcher.py          # multi-candidate arbitration on top of session.py + candidate.py
│   ├── test_bottom.py         # pytest suite for bottom.py
│   ├── test_crypto_backend.py # pytest suite for crypto_backend.py
│   ├── test_keystore.py       # pytest suite for keystore.py
│   ├── test_session.py        # pytest suite for session.py
│   ├── test_candidate.py      # pytest suite for candidate.py
│   ├── test_dispatcher.py     # pytest suite for dispatcher.py
│   └── __init__.py            # re-exports the public API from bottom.py
├── KEM-MAKE-2026.asn1         # hand-written ASN.1 schema; documentation only, see below
├── asn1/                      # vendored, verbatim reference modules from the relevant RFCs --
│                               # KEM-MAKE-2026.asn1 imports canonical OIDs/classes from these
│                               # rather than redefining them locally, where one exists
├── features/                  # Gherkin feature files (BDD)
│   ├── *.feature
│   └── steps/
│       ├── bottom.py          # step defs for the bottom-layer features (currently empty)
│       └── security.py        # step defs for kem_key_material.feature (partial)
├── doc/                       # reference material: FIPS 203, RFC 5084/5116/5652/8103/8933/9935, paper.pdf
└── bootstrap                  # sourced (not run) -- creates a venv and installs everything
```

There are no `requirements.txt`/`requirements-dev.txt` files — every
dependency, including dev-only ones, lives in `pyproject.toml`'s
`[project.dependencies]` and `[project.optional-dependencies.dev]`, pinned
with `==` throughout. See [Requirements
pinning](#requirements-pinning) for why.

## Installation

```bash
source bootstrap
```

**This must be sourced, not executed** (`source bootstrap` or
`. bootstrap`, not `./bootstrap`) — it activates a venv in your current
shell, which only works if `.venv/bin/activate` runs in that same shell
rather than a subprocess. It creates `.venv`, activates it, upgrades
`pip`, and runs `pip install -e ".[dev]"`, which installs the package
itself (editable) plus every runtime and dev dependency in one step.
Afterward, `import kem_make` / `from kem_make import KemPublicKey` work
directly, no `PYTHONPATH` needed.

```bash
pytest src/kem_make -v
behave
```

## Message structures

Five PDUs, wrapped in a versioned envelope:

```
MakeMessage
├── version   (INTEGER, DEFAULT 0, omitted from DER when default)
├── cid       (OCTET STRING, 128-bit binary UUID)
└── payload   (CHOICE, tagged [0]-[4])
    ├── [0] SessionInitRequest           { ct1, keyIdB, pkAStar, keyIdA, acceptableAeads }
    ├── [1] SessionInitResponse          { keyIdB, pkBStar, ct2, ct3, nB, chosenAead }
    ├── [2] SessionCompletionRequest     { cM, ct4, nA }
    ├── [3] SessionCompletionResponse    { hM, m? }
    └── [4] Message                      { seq, m }
```

`cM` on `SessionCompletionRequest` already *is* the false-start payload —
the encrypted application message Alice sends riding along with handshake
completion, before Bob has acknowledged. There's deliberately no separate
`m` field there; one would just duplicate what `cM` already carries.

`cM` must never be empty — an empty ciphertext encrypts zero bytes of
plaintext, which is known-plaintext by construction regardless of key, so
it's rejected outright rather than accepted as a valid (if pointless)
false-start message. This is enforced on `build()`, on `load()`, and on
`dump()` itself — the last of those is what actually matters, since
`SessionCompletionRequest` is constructed via a raw dict literal
everywhere else in this codebase, not exclusively through `build()`, so
`dump()` is the one chokepoint every send path goes through regardless of
construction method. Raises `EmptyFalseStartPayload`. `SIZE(1..MAX)` in
`KEM-MAKE-2026.asn1` expresses the same constraint directly in the grammar.
This is a structural floor (non-zero length), not a cryptographic one —
it doesn't enforce a real AEAD's actual minimum ciphertext length (e.g. a
16-byte tag); that's a separate concern for whatever layer actually knows
which AEAD was negotiated.

`m` on `SessionCompletionResponse` is `OCTET STRING OPTIONAL` (tagged
`[0]`) — present only when Bob's own early-data optimization is used,
otherwise absent from the wire entirely (not an empty string). This one
does earn its keep: `hM` is only an acknowledgment hash, not a payload, so
`m` is the only place a false-start reply from Bob could go.

`Message` is the post-handshake application-data PDU: `seq` is a
per-direction sequence number, `m` is the opaque payload. **`seq` is
scoped per direction** — each peer keeps its own independent counter, so
the same `seq` value can legitimately occur once from each peer within a
session. This is safe (not a collision risk) because each direction has
its own independently derived session key, out of the same HKDF that
produces the other session key material — the pair `(direction key, seq)`
is what must be unique, not `seq` alone. There is no per-message nonce
field on `Message`.

`keyIdA` identifies Alice's own static public key, so Bob can look her up
by her registered identity — it must be built from Alice's *static* key,
not from `pkAStar` (her ephemeral key for this session), since the
ephemeral key was never registered anywhere for Bob to look up.

`keyIdB` identifies the recipient key `ct1` was actually encapsulated
against. This lets Bob, if he holds more than one static key (e.g. across
a key rotation), pick the matching private key directly by comparing
`keyIdB` against a `KeyId` he computes himself from each candidate public
key, rather than attempting decapsulation blind against every key he
holds.

`acceptableAeads` (`SessionInitRequest`) and `chosenAead`
(`SessionInitResponse`) negotiate the AEAD algorithm: a list of bare
`OBJECT IDENTIFIER`s the initiator will accept, and the single OID the
responder picked. These are bare OIDs, not full `AlgorithmIdentifier`
structures — this is capability negotiation, not the AEAD's own
per-message parameters (nonce, ICV length, etc.), which are handled
elsewhere. `AEAD_OIDS` in `bottom.py` has the currently known algorithms
(AES-256-GCM per RFC 5084, ChaCha20-Poly1305 per RFC 8103) —
AES-128-GCM and AES-192-GCM deliberately not included, since neither is
used anywhere in this project.
`acceptableAeads` deliberately accepts unrecognized OIDs on load — it's
peer-advertised and forward compatibility matters there — while
`chosenAead` should be checked against the OIDs actually offered at the
protocol layer, since the ASN.1 structure alone can't cross-reference the
two separate PDUs.

## Quick usage

```python
import uuid
from kem_make import (
    MakeMessage, SessionInitRequest, KemPublicKey, KemCiphertext, KeyId,
    AeadAlgorithmList,
)

cid = uuid.uuid4()
pk_a_star = KemPublicKey.build(pk_a_star_bytes, level=768)   # Alice's ephemeral key, 512/768/1024
ct1 = KemCiphertext.build(ct_bytes, level=768)                # encapsulated against Bob's static key

key_id_a = KeyId.build(pk_a_static)   # hashes Alice's STATIC key, not pk_a_star -- Bob looks her up by this
key_id_b = KeyId.build(pk_b_static)   # identifies which of Bob's keys ct1 was made against

req = SessionInitRequest({
    "ct1": ct1,
    "key_id_b": key_id_b,
    "pk_a_star": pk_a_star,
    "key_id_a": key_id_a,
    "acceptable_aeads": AeadAlgorithmList.build(["aes256-gcm", "chacha20-poly1305"]),
})

msg = MakeMessage.build(cid, "session_init_request", req)
der = msg.dump()

# ... send der over the wire ...

parsed = MakeMessage.load(der)      # raises on malformed/non-canonical input
assert parsed.correlation_id == cid
assert parsed["payload"].name == "session_init_request"
```

## Design decisions worth knowing before extending this

- **DER only, BER is rejected.** Every `load()` re-derives the canonical DER
  encoding from the parsed value (`dump(force=True)`) and compares it
  byte-for-byte against the input. If they differ, the input was BER (or
  otherwise non-canonical) and is rejected with `NonCanonicalEncoding`.
  `force=True` is essential here — a plain `.dump()` returns asn1crypto's
  cached original bytes and silently no-ops the check. `test_bottom.py`
  has a regression test for exactly this.
- **KeyId hashes the whole `KemPublicKey` SEQUENCE**, not just the raw key
  bytes. This binds the algorithm into the identifier: the same key bytes
  under a different (or spoofed) algorithm label produce a different
  `KeyId`. `hashAlgorithm` in `KeyId` only describes how the ID itself was
  computed — it says nothing about the KEM algorithm of the underlying key.
- **KEM public keys and ciphertexts carry an explicit `AlgorithmIdentifier`**
  with `parameters` absent (not `NULL`) per RFC 9935, and are length-checked
  against FIPS 203 Table 3 on both the build and load paths — so a
  truncated or padded frame is rejected regardless of whether the bad data
  originated locally or over the wire.
- **Unknown OID vs. wrong length are distinct exceptions**
  (`UnknownKemAlgorithm` vs. `KemLengthMismatch`) since "unsupported KEM"
  and "malformed frame under a supported KEM" likely warrant different
  protocol responses.
- **`version` uses DER's DEFAULT-omission rule**, not `OPTIONAL`. A v1
  message (`version=0`) omits the field entirely on the wire; `.native`
  still reports `0` when absent.
- **`Message.seq` is per-direction, not session-wide, and there is no
  per-message nonce.** Uniqueness comes from `(direction session key,
  seq)`, since each direction's key is independently derived via HKDF.
  Don't use `seq` alone anywhere that needs a session-wide-unique value
  (e.g. a replay cache shared across both directions) — key it by
  direction as well.
- **AEAD negotiation uses bare OIDs, not `AlgorithmIdentifier`s.**
  `acceptableAeads`/`chosenAead` only need to name an algorithm for
  negotiation purposes; the actual per-message AEAD parameters (nonce,
  ICV length) live elsewhere, not in these fields. Note that some of these
  same OIDs (the AES-GCM family, per RFC 5084) require a *present*
  `parameters` field when used as a real `AlgorithmIdentifier` for
  encryption — that rule doesn't apply here since these fields aren't
  full `AlgorithmIdentifier`s at all, just the bare OID.
- **`acceptableAeads` tolerates unrecognized OIDs; `chosenAead` should be
  checked at the protocol layer.** The request's list is peer-advertised
  and may include algorithms this implementation doesn't know about yet
  (forward compatibility), so `AeadAlgorithmList` doesn't reject unknown
  OIDs on load. The response's single chosen algorithm should be validated
  against what was actually offered — but that's a cross-PDU check the
  ASN.1 structure alone can't perform, since the request and response are
  separate objects; it belongs in the protocol implementation, not here.

## Key directory (`keystore.py`)

Encrypted on-disk storage for public and private keys, ahead of the
top-layer protocol logic. It's a real filesystem directory, not one
monolithic file — `<dir>/header.der`, `<dir>/public/<hex-sha256>.der`,
`<dir>/private/<hex-sha256>.der>`, plus a lazily-created
`<dir>/alt_index.der` — so adding or updating one key is a single atomic
file write rather than a rewrite of the whole store.

```python
from kem_make.keystore import KeyDirectory

kd = KeyDirectory.create("./keys", passphrase=b"correct horse battery staple")
key_id = kd.add_public_key(pk)          # KemPublicKey from bottom.py
kd.add_private_key(pk, private_key_bytes)

pk_again = kd.get_public_key(key_id)
priv_bytes = kd.get_private_key(key_id)  # bytearray; zero it yourself when done
kd.close()

# Later, in a new process:
kd = KeyDirectory.open("./keys", passphrase=b"correct horse battery staple")
```

Key points (the module's own docstring has the full reasoning for all of
these):

- **Passphrase → master key** via PBKDF2-HMAC-SHA256, 600,000 iterations
  by default (OWASP's current cited PBKDF2 minimum, chosen for FIPS
  alignment with the rest of this project — Argon2id is OWASP's overall
  top pick if FIPS compliance isn't actually a requirement here). **The
  master key is derived, never stored** — `header.der` holds only the
  PBKDF2 salt, iteration count, and a verification tag, never the key
  itself. `test_keystore.py` backs this with a test that scans every byte
  of every file the module writes, across several passphrases and
  iteration counts, and confirms the raw master key never appears in any
  of them.
- **Every private key gets its own KEK**, derived via HKDF-SHA256 from
  the master key with a fresh random salt and an info field that binds in
  a domain-separation label plus that key's own identity. Compromising
  one key's KEK reveals nothing about any other key's.
- **Private keys are wrapped with AES-256 Key Wrap with Padding (RFC 3394
  / RFC 5649)**, not an AEAD — there's no nonce to manage, since AES-KW
  has none; it's deterministic instead (same key bytes + same KEK always
  produces the same wrapped output), which is fine here specifically
  because no two entries ever share a KEK. Its own built-in integrity
  check catches tampering on unwrap, raising `PrivateKeyUnwrapFailed`.
- **Public keys are never encrypted** — there's nothing to protect — but
  they ARE integrity-protected: each entry carries an HMAC-SHA256 tag
  from a per-entry MAC key (same HKDF-from-master-key pattern as the
  private-key KEKs), with the entry's own filename bound into the
  derivation. That last part specifically catches an attacker swapping
  two validly-MAC'd entries between each other's filenames — confirmed
  with a dedicated test, not just asserted.
- **Key IDs are cached, never recomputed.** SHA-256 is the default and
  always present; a lookup under a different digest computes it once,
  persists it back onto that key's entry, and records it in
  `alt_index.der` so a later direct lookup by that alternate hash is
  still an index hit, not a rescan-and-rehash of every stored key.
  `alt_index.der` is itself MAC-protected the same way public key entries
  are, but it's treated as an untrusted hint regardless: after resolving
  a filename through it, the resolved entry's own (independently
  verified) key list is cross-checked to actually contain the KeyId that
  was asked for. That cross-check is what actually matters — a
  corrupted or attacker-redirected `alt_index.der` could otherwise point
  a lookup at a different, individually-valid entry that would still
  pass its own MAC (since it isn't tampered, it's just the wrong one).
  Confirmed exploitable against an earlier version of this code before
  that check existed.
- **Wrong-passphrase detection and key lookups both use constant-time
  comparison.** The passphrase check uses a dedicated HKDF-derived check
  tag compared with `hmac.compare_digest`; `KeyId` lookups (both the
  primary-entry check and the `alt_index.der` lookup) use a
  `_key_hash_equal` helper wrapping the same function. A `KeyId`
  identifies a *public* key and isn't secret the way a password or KEK
  is, but this module treats every digest comparison as constant-time by
  policy regardless of whether a specific case is provably exploitable —
  it's free, and it means never having to re-argue "is this one actually
  exploitable" in a future review. CPython's `bytes.__eq__` is a
  short-circuiting comparison and not constant-time, so any comparison of
  digest/hash material added to this module later must use one of these
  helpers, not `==`.
- **Best-effort zeroing** of the master key, per-key KEKs, and decrypted
  private key bytes via an explicit `_zero()` helper — genuinely
  best-effort, not a guarantee; CPython's allocator, GC, and any internal
  copies made by `cryptography` itself are outside this module's control.
  `get_private_key()` returns a `bytearray`, not `bytes`, specifically so
  callers can zero it themselves once done.
- **File permissions**: `0700` on the directory and its `public`/`private`
  subdirectories, `0600` on the header and every private key file, `0644`
  on public key files — enforced with `os.chmod` after creation, not left
  to the process umask.
- **All writes are atomic** — temp file in the same directory, then
  `os.replace()` — so a crash mid-write can't leave a half-written file
  that later parses as valid-but-wrong.
- **DER-only, same as everywhere else in this project.** All four on-disk
  record types (`KeystoreHeader`, `StoredPublicKeyEntry`,
  `StoredPrivateKeyEntry`, `AltIndex`/`AltIndexEntry`) enforce DER
  canonicality on `load()` via the same `_require_der` helper `bottom.py`
  uses, confirmed by feeding each one a non-minimal-length BER encoding
  in `test_keystore.py` and checking it's rejected.

Not yet built: no passphrase-change/re-encryption support, no
keystore-wide locking against concurrent writers. Flagged explicitly in
the module docstring rather than silently left out.

## Session layer (`session.py`)

The mutually-authenticated handshake and established-session traffic
from `main.pdf`, run on top of `bottom.py`'s wire structures as a
transport-agnostic state machine. One `Session` instance is one
handshake attempt for one `cid`, either role.

```python
from kem_make.session import Session, Role

alice = Session(Role.INITIATOR, alice_key_id, key_lookup)
alice.initiate(bob_key_id, now=time.monotonic())
wire_bytes = alice.get_pdu()          # send this over your transport

# elsewhere, on receipt:
alice.post_pdu(incoming_bytes)
result, next_deadline = alice.update(now=time.monotonic())
if result is UpdateResult.PAYLOAD_READY:
    plaintext = alice.get_payload()
```

Key points (the module's own docstring has the full reasoning for all of
these):

- **Push-in / pull-out / crank, not callbacks.** `post_pdu()`/
  `post_payload()` only enqueue; `update(now)` is where every state
  transition, crypto operation, and retry/TTL decision actually happens;
  `poll_*()`/`get_*()` let the caller pull output whenever it's safe to.
  Deliberately not callback-based — a callback firing synchronously from
  inside `post_pdu()` would put the layer's own internals on the call
  stack exactly where a handler is likely to reenter it, and a pure state
  machine with no callbacks is far easier to drive from a test.
- **Retries resend the exact bytes already sent, never regenerated
  ones.** This is a correctness requirement, not a style choice:
  regenerating ephemeral keys on retry would produce a structurally
  valid but cryptographically different message, silently diverging from
  whatever the peer already derived from the original.
- **Duplicate detection is a single byte-exact slot, not a history.**
  `_last_received`/`_last_sent` represent "the pair relevant to the step
  currently being waited on," overwritten on every real state
  transition. A byte-exact match against `_last_received` triggers an
  exact resend of `_last_sent`, never re-entering the handshake logic —
  sufficient specifically because DER is canonical throughout this
  project, so semantically-identical and byte-identical are the same
  test.
- **The responder never retries; its deadline is a pure TTL.** Bob only
  ever reacts to Alice's retries. If Bob is seeing repeated retries of
  the same PDU, that means his own replies aren't reaching Alice, and no
  amount of holding state open longer fixes a broken return path.
- **Two independent directional session keys, not one shared key.**
  `main.pdf`'s literal `H` function produces a single `k`; extended here
  (following `bottom.py`'s own pre-existing `Message.seq` commentary)
  into `(key_a2b, iv_a2b, key_b2a, iv_b2a)` from one HKDF salt/IKM,
  differentiated by `info` label per direction. Per-message nonces are
  `IV XOR seq` — the same construction TLS 1.3 uses for its per-record
  nonce — rather than random, since every `Message` already carries
  `seq` and random nonces would need their own uniqueness bookkeeping
  this project already does better with a sequence number.
- **A "nothing to send yet" false-start message relies on the AEAD tag,
  not a sentinel.** `c_m` can never be empty (see `bottom.py`'s
  `EmptyFalseStartPayload`); encrypting an *empty plaintext* still
  produces a non-empty ciphertext (the tag alone), satisfying that
  constraint as a natural byproduct of using a real AEAD rather than a
  special-cased placeholder value.
- **No wire-level error message exists anywhere in this protocol.**
  Every failure path either raises a local, Python-only exception
  (`HandshakeFailed`, `UnexpectedPDU`) for the caller to act on, or —
  for retry/TTL exhaustion specifically — simply produces no further
  output. Nothing here ever tells a peer, legitimate or attacking, that
  something went wrong.
- **`fork()` exists for exactly one reason**: a `cid` may have more than
  one plausible `SessionInitResponse` in flight (see `dispatcher.py`),
  and giving each candidate its own sibling — sharing pre-response state
  but with independent output queues — is how more than one gets tried.
  The ephemeral private key is reconstructed from its raw seed bytes
  rather than copied by reference or deep-copied, matching this
  project's established pattern elsewhere rather than relying on the
  `cryptography` library's undocumented copy support for its key
  objects.

Known placeholder, not discussed as a design decision so much as a
choice that had to be made somehow: established-session anti-replay is
strict-monotonic-`seq` only, no sliding window, no tolerance for
reordering — fine for a reliable ordered transport, likely wrong as-is
for anything else.

## Candidate store (`candidate.py`)

Standalone, protocol-agnostic bookkeeping for unauthenticated
first-flight PDUs — the actual DoS-mitigation primitive underneath
`dispatcher.py`. Does no cryptography and parses no PDU; callers hand it
opaque `(received, sent)` byte pairs per `cid` and tell it when a
candidate has been cryptographically confirmed.

The threat this exists for: KEM encapsulation only needs a *public* key,
so anyone holding Alice's and Bob's already-public keys can forge a
structurally valid `SessionInitResponse` (or `SessionInitRequest`) under
a given `cid`, without holding any private key at all. The forgery is
only provably wrong once someone actually derives and confirms the
session key — until then, a peer holding a `cid` may have more than one
plausible candidate for it.

- **Bounded two ways**: a small per-`cid` cap (default 3), and a coarser
  global cap (default 1024) across every `cid` at once.
- **Promotion is total**: the instant a candidate is cryptographically
  confirmed, every sibling for that `cid` is discarded, including the
  winner itself — its bookkeeping moves to whatever confirmed the
  session, not this store.
- **TTL is fixed, deliberately not sliding.** A run of legitimate
  retries proves the request path works and the response path doesn't —
  extending the deadline wouldn't fix a broken return path, and would
  let an attacker who captured one legitimate eliciting message replay
  it indefinitely to keep a candidate alive forever for free, since a
  matching duplicate costs nothing but a cache hit. Tested explicitly: a
  matching lookup does not extend `expires_at` as a side effect.
- **Not thread-safe** — callers sharing one instance across threads must
  serialize access themselves.

## Multi-candidate dispatcher (`dispatcher.py`)

Arbitrates the actual Mallory scenario: after Alice sends one
`SessionInitRequest` under some `cid`, she may legitimately receive more
than one candidate `SessionInitResponse` under that same `cid` — the
real Bob's, plus zero or more forged ones from anyone who observed the
request.

```python
from kem_make.dispatcher import Dispatcher

alice = Dispatcher(key_lookup)
cid = alice.initiate(alice_key_id, bob_key_id, now=time.monotonic())
while alice.poll_pdu():
    transport.send(alice.get_pdu())

# elsewhere, on receipt of anything (real Bob's response, or a forgery):
alice.post_pdu(incoming_bytes, now=time.monotonic())
result, next_deadline = alice.update(now=time.monotonic())
```

- **Asymmetric by design, verified directly before writing any code, not
  assumed.** A forged `SessionInitRequest` claiming to be Alice can
  never actually complete a handshake — doing so requires decapsulating
  `ct1`, which was encapsulated by the real Alice against the real Bob's
  static public key, using only Bob's real static private key. A forger
  has no way to obtain that, regardless of which side of the exchange
  they're impersonating (checked the mirror-image case too: forging as
  "Bob" instead leaves the forger permanently missing a different
  secret, for the same structural reason). So the responder side needs
  only `CandidateStore`'s existing per-`cid`/global caps for a *single*
  `Session` per `cid` — all the real arbitration is on the initiator side.
- **`CandidateStore` is reused for both roles' first real
  response-generating step.** Responder: `(SessionInitRequest received,
  SessionInitResponse sent)`. Initiator: `(SessionInitResponse received,
  SessionCompletionRequest sent)`, one entry per fork. Same caps, same
  TTL, same store.
- **Promotion is immediate and total**, not merely eventual — the
  instant any fork reaches `ESTABLISHED`, every sibling for that `cid`
  is discarded right there, not on the next `update()` tick, and not
  contingent on a losing candidate ever producing a reply.
- **`update(now)` mirrors `Session`'s own `(result, next_deadline)`
  contract** rather than returning nothing, so a `Dispatcher` can be
  driven the same way a bare `Session` can, just at the
  multi-session level.
- **`close(cid)`** is the only way to release an established session —
  there's deliberately no idle-timeout or max-lifetime policy for
  established sessions here; that's a decision for whatever sits above
  this, which knows what "the session is done" actually means for the
  application.
- **A responder session that fails validation** (unknown claimed
  identity, no mutual AEAD) is cleaned up immediately rather than left
  to linger at `INITIAL` until its `CandidateStore` entry's TTL expires
  — it can never become anything but permanently invalid, so there's no
  reason to wait.

Verified end to end, not just unit-by-unit: a forged
`SessionInitResponse`, built using only public information via the same
encapsulation calls `session.py` itself uses (no shortcuts, no mocked
crypto), racing against a real `Session`-driven Bob, in both
arrival orders — forged-first and real-first both correctly end with
Alice established with the real Bob, with the forged fork discarded, and
the forger cannot complete the handshake even by actively trying to
respond to their own fork with a fabricated confirmation.

Two real, systemic bugs were caught by that end-to-end test rather than
by any single unit test: the first working version of message delivery
processed a candidate's incoming PDU correctly but never actually moved
the resulting output into the outgoing queue — fixed by merging that
into one code path so the bug class can't recur by construction, rather
than auditing every call site by hand — and `update()` initially never
cranked already-established sessions at all, so `post_payload()` on a
live session queued correctly but nothing ever processed it.

## Keeping the schema in sync

`KEM-MAKE-2026.asn1` is maintained by hand. asn1crypto has no schema exporter (nor
does pyasn1), so there's no tooling guarantee that the `.asn1` file and
`bottom.py` agree — any field, tag, or type change to one **must** be
mirrored in the other manually. `bottom.py` is authoritative; the `.asn1`
file exists for readability and for interop with other ASN.1 toolchains.

**`KEM-MAKE-2026.asn1` does not compile with any tool currently in this repo, and
that's expected.** `KemPublicKey`, `KemCiphertext`, and `KeyId` use RFC
5912's real, canonical parameterized `AlgorithmIdentifier{}` (information
object classes, X.681–683), imported from `AlgorithmInformation-2009` /
`PKIX1-PSS-OAEP-Algorithms-2009` — both now vendored under `asn1/`, along
with `NistAlgorithm`, `X509-ML-KEM-2025` (RFC 9935), and
`CMS-AEADChaCha20Poly1305` (RFC 8103), which supply the canonical
ML-KEM/AES-256-GCM/ChaCha20-Poly1305 OIDs this schema now imports rather
than redefining locally. Vendoring the real files didn't change the
conclusion, but it's worth noting the failure re-verified differently
than before: `asn1tools` now fails just *parsing*
`AlgorithmInformation-2009.asn1` itself, at `SIGNATURE-ALGORITHM`'s
`&HashSet` field (a SET-valued class field its parser doesn't support),
before ever reaching this schema's own use of `AlgorithmIdentifier{}`.
Three independently-built open-source ASN.1 compilers were tested against
this exact construct (`asn1tools`, Erlang/OTP's `asn1ct`, Heimdal's
`asn1_compile`) and none can fully resolve it — `asn1ct` resolves it
directly but crashes specifically when it's wrapped in a reusable
parameterized type; Heimdal's grammar has no support for information
object classes whatsoever (the `&`-field syntax doesn't even tokenize).
See the schema file's own comments for the full account.

This has a wider consequence than just those three types: `asn1tools`
requires a module's `IMPORTS` to resolve before it can compile *anything*
in that module, and `MakePayload` (a `CHOICE`) references
`SessionInitRequest`/`SessionInitResponse`, which reference the
`AlgorithmIdentifier`-bearing types — so the failure isn't scoped to
`KemPublicKey`/`KemCiphertext`/`KeyId`, it makes the **entire file**
uncompilable as a single unit, including `SessionCompletionResponse`,
`Message`, and `AcceptableAeadList`, none of which touch
`AlgorithmIdentifier` at all.

`KEM-MAKE-2026.asn1` is therefore documentation only from here on — a spec
reference for readers, not a tool-verified artifact. `bottom.py` remains
the authoritative, tested definition of the actual wire format, and its
DER output is byte-for-byte identical to what the canonical schema
describes regardless (`ALGORITHM.&id`/`.&Params` still resolve to a bare
`OBJECT IDENTIFIER` + optional open type either way — only the schema's
formal expressiveness differs, not the bytes on the wire).

`test_bottom.py`'s three schema cross-check tests
(`test_schema_matches_python_classes_for_session_completion_response`,
`_for_message`, `_for_acceptable_aeads`) skip gracefully with an explicit
reason rather than fail, since this is now a permanent, expected state
rather than a transient environment problem. If a more complete X.681–683
implementation ever becomes available (a commercial compiler like
Objective Systems ASN1C or OSS Nokalva is the likeliest candidate, though
untested here) and you vendor the real imported modules, these tests will
start running for real again with no code changes needed.

## Requirements pinning

`pyproject.toml` pins `asn1crypto` with `==` rather than `>=`. The DER
canonicality check depends on `dump(force=True)` behaving as it currently
does internally, which isn't part of asn1crypto's public API contract. If
you bump the pin, re-run `test_bottom.py` (particularly
`test_non_minimal_length_ber_is_rejected` and
`test_canonicality_check_is_not_a_silent_noop`) before trusting the new
version.

`cryptography` is similarly pinned exactly (`==49.0.0`), since that's the
release where the official wheels first bundle OpenSSL≥3.5, which is what
makes ML-KEM available without a custom AWS-LC/BoringSSL build — see the
comment beside it in `pyproject.toml` for the full reasoning, and
`crypto_backend.py`'s `check_backend()` for why the pin alone isn't
sufficient proof the backend actually works.

## Known issues worth a look

**Fixed:** `pyproject.toml` was missing (package wasn't installable —
confirmed via `pip install -e .` failing outright) and
`src/kem_make/__init__.py` was empty (nothing re-exported at the top
level, so `features/steps/security.py`'s `from kem_make import
KemPublicKey` couldn't resolve). Both are fixed now: `pip install -e
".[dev]"` installs cleanly, `from kem_make import KemPublicKey` and
`from kem_make.bottom import KemPublicKey` both work, the full test suite
passes with a plain `pytest src/kem_make` (167 passed, no `PYTHONPATH`
needed), and `behave` runs without crashing on import.

Still open:

- **`features/steps/` only has `bottom.py` and `security.py`.** Every
  scenario in `key_id.feature`, `message_envelope.feature`,
  `post_handshake_message.feature`, `session_handshake.feature`,
  `key_directory_*.feature`, `crypto_backend.feature`,
  `candidate_store.feature`, `session_handshake_flow.feature`,
  `session_retry_and_timeout.feature`, and
  `session_forged_candidates.feature` is undefined as far as `behave` is
  concerned. Only `kem_key_material.feature` has any step implementations
  (in `security.py`), and those are partial. Expected, not a bug —
  step definitions are being written separately, by hand.
- **`security.py`'s remaining stubs use `StepNotImplementedError`** — a
  good pattern for distinguishing genuinely-unwritten steps from steps
  that intentionally do nothing, worth keeping. Two of the stubs (the
  ML-KEM-512 ciphertext-material and level-512 `KemCiphertext` build
  steps) no longer match anything in `kem_key_material.feature`, since
  the 512 row was removed from both `Examples` tables there (consistent
  with `crypto_backend.py` dropping ML-KEM-512 support) — these two step
  defs are now dead code and can be deleted.
- **A duplicate `from behave.api.pending_step import
  StepNotImplementedError`** appears both at the top and the very
  bottom of `security.py` — harmless, but looks like leftover output
  from a stub-generation pass that didn't dedupe imports.
- **`test_bottom.py` is missing the three schema cross-check tests**
  (`test_schema_matches_python_classes_for_session_completion_response`,
  `_for_message`, `_for_acceptable_aeads`) and the `_compile_schema_or_skip()`
  helper that makes them skip gracefully now that `KEM-MAKE-2026.asn1` is
  documentation-only. Worth confirming whether dropping them was
  deliberate (reasonable, since they'll now always skip) or this file
  predates that change.
- **Established-session anti-replay is strict-monotonic-`seq` only** —
  no sliding window, no tolerance for reordering. Fine for a reliable
  ordered transport; likely wrong as-is for anything else.
- **No idle-timeout or max-lifetime policy for established sessions**
  beyond `Dispatcher.close()`, which only ever removes a session when a
  caller explicitly says to. Deliberately left to whatever sits above
  the session layer, which knows what "the session is done" actually
  means for the application — not guessed at here.
- **No integration test against a real `KeyDirectory`.**
  `test_session.py`/`test_dispatcher.py` use a minimal in-memory fake
  key lookup throughout; `KeyLookup` is currently only a structural
  (`Protocol`) guarantee against the real `keystore.KeyDirectory`, never
  exercised end to end against it.

None of these affect `bottom.py`, `crypto_backend.py`, `keystore.py`,
`session.py`, `candidate.py`, `dispatcher.py`, or `KEM-MAKE-2026.asn1`
themselves — those are unchanged from their last verified state and
still pass their existing tests.
