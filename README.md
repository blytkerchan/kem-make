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
│   ├── test_bottom.py         # pytest suite for bottom.py
│   ├── test_crypto_backend.py # pytest suite for crypto_backend.py
│   └── __init__.py            # re-exports the public API from bottom.py
├── kem-make.asn1              # hand-written ASN.1 schema; documentation only, see below
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
`kem-make.asn1` expresses the same constraint directly in the grammar.
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
(AES-128/192/256-GCM per RFC 5084, ChaCha20-Poly1305 per RFC 8103).
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

## Keeping the schema in sync

`kem-make.asn1` is maintained by hand. asn1crypto has no schema exporter (nor
does pyasn1), so there's no tooling guarantee that the `.asn1` file and
`bottom.py` agree — any field, tag, or type change to one **must** be
mirrored in the other manually. `bottom.py` is authoritative; the `.asn1`
file exists for readability and for interop with other ASN.1 toolchains.

**`kem-make.asn1` does not compile with any tool currently in this repo, and
that's expected.** `KemPublicKey`, `KemCiphertext`, and `KeyId` use RFC
5912's real, canonical parameterized `AlgorithmIdentifier{}` (information
object classes, X.681–683), imported from `AlgorithmInformation-2009` /
`PKIX1-PSS-OAEP-Algorithms-2009`. Those imported modules aren't vendored
into this repo, and even if they were: three independently-built
open-source ASN.1 compilers were tested against this exact construct
(`asn1tools`, Erlang/OTP's `asn1ct`, Heimdal's `asn1_compile`) and none can
fully resolve it — `asn1tools` fails to resolve the governed open type at
all; `asn1ct` resolves it directly but crashes specifically when it's
wrapped in a reusable parameterized type; Heimdal's grammar has no support
for information object classes whatsoever (the `&`-field syntax doesn't
even tokenize). See the schema file's own comments for the full account.

This has a wider consequence than just those three types: `asn1tools`
requires a module's `IMPORTS` to resolve before it can compile *anything*
in that module, and `MakePayload` (a `CHOICE`) references
`SessionInitRequest`/`SessionInitResponse`, which reference the
`AlgorithmIdentifier`-bearing types — so the failure isn't scoped to
`KemPublicKey`/`KemCiphertext`/`KeyId`, it makes the **entire file**
uncompilable as a single unit, including `SessionCompletionResponse`,
`Message`, and `AcceptableAeadList`, none of which touch
`AlgorithmIdentifier` at all.

`kem-make.asn1` is therefore documentation only from here on — a spec
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
passes with a plain `pytest src/kem_make` (55 passed, no `PYTHONPATH`
needed), and `behave` runs without crashing on import.

Still open:

- **`features/steps/bottom.py` is empty.** Every step in
  `key_id.feature`, `message_envelope.feature`,
  `post_handshake_message.feature`, and `session_handshake.feature` is
  undefined as far as `behave` is concerned — confirmed via a full
  `behave` run: 2 scenarios pass, 48 error, 209 steps undefined. Only
  `kem_key_material.feature` has any step implementations (in
  `security.py`), and those are partial.
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
  helper that makes them skip gracefully now that `kem-make.asn1` is
  documentation-only. Worth confirming whether dropping them was
  deliberate (reasonable, since they'll now always skip) or this file
  predates that change.

None of these affect `bottom.py`, `crypto_backend.py`, or `kem-make.asn1`
themselves — those three are unchanged from the last verified state and
still pass their existing tests.
