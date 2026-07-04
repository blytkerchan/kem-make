# KEM-MAKE Protocol Messages

DER-encoded message structures for the KEM-MAKE key-establishment protocol
(https://applied-paranoia.com/assets/2026/kem-make.pdf), built on
[asn1crypto](https://pypi.org/project/asn1crypto/).

## Files

| File                    | Purpose                                                                 |
|-------------------------|--------------------------------------------------------------------------|
| `kem_make.py`           | The message structures themselves. This is the authoritative definition. |
| `kem-make.asn1`         | Hand-written ASN.1 module mirroring `kem_make.py`, for spec readability and interop with other ASN.1 toolchains. **Not tool-generated** — see [Keeping the schema in sync](#keeping-the-schema-in-sync). |
| `test_kem_make.py`      | pytest suite covering validation, optional fields, and DER canonicality. |
| `features/*.feature`    | Gherkin feature files describing the same behaviour in BDD form. |
| `requirements.txt`      | Runtime dependencies. |
| `requirements-dev.txt`  | Dependencies needed to run the test suite and cross-validate the schema. |

## Installation

```bash
pip install -r requirements.txt
```

For running tests / cross-validating the schema:

```bash
pip install -r requirements-dev.txt
pytest test_kem_make.py -v
```

## Message structures

Five PDUs, wrapped in a versioned envelope:

```
MakeMessage
├── version   (INTEGER, DEFAULT 0, omitted from DER when default)
├── cid       (OCTET STRING, 128-bit binary UUID)
└── payload   (CHOICE, tagged [0]-[4])
    ├── [0] SessionInitRequest           { ct1, pkAStar, keyIdA }
    ├── [1] SessionInitResponse          { keyIdB, pkBStar, ct2, ct3, nB }
    ├── [2] SessionCompletionRequest     { cM, ct4, nA, m? }
    ├── [3] SessionCompletionResponse    { hM, m? }
    └── [4] Message                      { seq, n, m }
```

`m` on `SessionCompletionRequest`/`SessionCompletionResponse` is
`OCTET STRING OPTIONAL` (tagged `[0]`) — present only when the early-data
optimization is used, otherwise absent from the wire entirely (not an
empty string).

`Message` is the post-handshake application-data PDU: `seq` is a
per-direction sequence number, `n` is a mandatory nonce, `m` is the opaque
payload. **`seq` is scoped per direction** — each peer keeps its own
independent counter, so the same `seq` value can legitimately occur once
from each peer within a session. `seq` is therefore *not* unique across
the whole session on its own; `n` is what must be relied on wherever
genuine uniqueness is required (e.g. deriving an AEAD nonce).

## Quick usage

```python
import uuid
from kem_make import (
    MakeMessage, SessionInitRequest, KemPublicKey, KemCiphertext, KeyId,
)

cid = uuid.uuid4()
pk_a_star = KemPublicKey.build(pk_bytes, level=768)   # 512, 768, or 1024
ct1 = KemCiphertext.build(ct_bytes, level=768)
key_id_a = KeyId.build(pk_a_star)                      # hashes the whole KemPublicKey DER

req = SessionInitRequest({
    "ct1": ct1,
    "pk_a_star": pk_a_star,
    "key_id_a": key_id_a,
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
  cached original bytes and silently no-ops the check. `test_kem_make.py`
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
- **`Message.seq` is per-direction, not session-wide.** Don't use `seq`
  alone anywhere that needs a value unique across the whole session (e.g.
  nonce derivation, replay caches keyed only by seq) — use `n`, or the
  pair `(direction, seq)`, instead. This is also why `n` is mandatory
  rather than optional on `Message`.

## Keeping the schema in sync

`kem-make.asn1` is maintained by hand. asn1crypto has no schema exporter (nor
does pyasn1), so there's no tooling guarantee that the `.asn1` file and
`kem_make.py` agree — any field, tag, or type change to one **must** be
mirrored in the other manually. `kem_make.py` is authoritative; the `.asn1`
file exists for readability and for interop with other ASN.1 toolchains.

`test_kem_make.py` cross-compiles `kem-make.asn1` with `asn1tools` and
confirms it produces byte-identical DER to `kem_make.py` in both
directions, for the types that don't require `ANY DEFINED BY` open-type
registration to encode cleanly through asn1tools
(`SessionCompletionResponse` and `Message`). `AlgorithmIdentifier`'s open-type
field is standard PKIX style and compiles fine, but fully exercising it
through asn1tools' encoder would need that registration set up separately
— it hasn't been, since it wasn't needed to validate what's changed so far.

## Requirements pinning

`requirements.txt` pins `asn1crypto` with `==` rather than `>=`. The DER
canonicality check depends on `dump(force=True)` behaving as it currently
does internally, which isn't part of asn1crypto's public API contract. If
you bump the pin, re-run `test_kem_make.py` (particularly
`test_non_minimal_length_ber_is_rejected` and
`test_canonicality_check_is_not_a_silent_noop`) before trusting the new
version.
