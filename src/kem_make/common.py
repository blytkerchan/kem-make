"""Common utilities for KEM-MAKE."""

class NonCanonicalEncoding(ValueError):
    """Raised when the input bytes parse but are not the unique DER encoding.

    DER is deterministic: for any value there is exactly one valid DER
    encoding. Re-dumping a correctly parsed object must therefore reproduce
    the input byte-for-byte. If it doesn't, the input was BER (or otherwise
    non-canonical) and must be rejected rather than silently accepted.
    """


def require_der(cls, encoded_data: bytes, obj):
    """Raise NonCanonicalEncoding if the input bytes are not canonical DER."""
    # force=True is essential here: asn1crypto's Sequence/Choice cache the
    # original parsed bytes and hand them straight back on a plain dump(),
    # so a naive dump() vs. input comparison is a silent no-op -- it just
    # compares the cache against itself. force=True discards the cache and
    # re-derives bytes from the parsed field values, which is the actual
    # canonical DER re-encoding we need to compare against.
    rebuilt = obj.dump(force=True)
    if rebuilt != bytes(encoded_data):
        raise NonCanonicalEncoding(
            f"{cls.__name__}: input is not canonical DER (BER/non-minimal "
            f"encoding rejected)"
        )
