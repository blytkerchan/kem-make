"""
KEM-MAKE protocol message structures.

Re-exports the public API of bottom.py so `from kem_make import
KemPublicKey` (etc.) works, matching how features/steps/security.py and
this package's own README already import it. bottom.py itself remains the
authoritative implementation; nothing here should contain logic.
"""

from .bottom import (
    # Constants
    MLKEM_OIDS,
    MLKEM_PK_LEN,
    MLKEM_CT_LEN,
    CID_LEN,
    AEAD_OIDS,
    # Functions
    aead_name,
    kem_alg,
    # Exceptions
    UnknownKemAlgorithm,
    KemLengthMismatch,
    InvalidCorrelationId,
    NonCanonicalEncoding,
    EmptyFalseStartPayload,
    # Structures
    KemPublicKey,
    KemCiphertext,
    KeyId,
    AeadAlgorithmList,
    SessionInitRequest,
    SessionInitResponse,
    SessionCompletionRequest,
    SessionCompletionResponse,
    Message,
    MakePayload,
    MakeMessage,
)

__all__ = [
    "MLKEM_OIDS",
    "MLKEM_PK_LEN",
    "MLKEM_CT_LEN",
    "CID_LEN",
    "AEAD_OIDS",
    "aead_name",
    "kem_alg",
    "UnknownKemAlgorithm",
    "KemLengthMismatch",
    "InvalidCorrelationId",
    "NonCanonicalEncoding",
    "EmptyFalseStartPayload",
    "KemPublicKey",
    "KemCiphertext",
    "KeyId",
    "AeadAlgorithmList",
    "SessionInitRequest",
    "SessionInitResponse",
    "SessionCompletionRequest",
    "SessionCompletionResponse",
    "Message",
    "MakePayload",
    "MakeMessage",
]
