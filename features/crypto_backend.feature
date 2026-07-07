# Security sub-layer for KEM-MAKE
Feature: Crypto backend capability check
  As an implementer of KEM-MAKE
  I want a single startup check that every cryptographic primitive
  KEM-MAKE needs actually works on the installed backend, not just that
  the classes import successfully
  So that a silently unsupported ML-KEM build, or a backend that runs
  without error but produces wrong output, turns into an immediate,
  actionable failure at startup rather than a confusing one deep inside
  a live handshake

  Background:
    Given a working cryptography backend

  Scenario: A fully working backend passes the check without raising
    When I run the crypto backend check
    Then the check passes without raising

  Scenario Outline: ML-KEM round-trips correctly at each supported level
    When I generate an ML-KEM-<level> key pair
    And I encapsulate against its public key
    And I decapsulate the resulting ciphertext with its private key
    Then the decapsulated shared secret equals the encapsulated one

    Examples:
      | level |
      | 768   |
      | 1024  |

  Scenario: ML-KEM-512 is deliberately not offered
    # Absent from pyca/cryptography's mlkem module entirely, consistent
    # with it being dropped from other recent implementations (e.g. Go's
    # standard library crypto/mlkem) for lack of real-world deployment.
    Then ML-KEM-512 is not among the levels the crypto backend check covers
    And exactly ML-KEM-768 and ML-KEM-1024 are covered

  Scenario: A broken ML-KEM primitive is caught, not silently ignored
    Given ML-KEM-768 key generation is broken on this backend
    When I run the crypto backend check
    Then the check fails with CryptoBackendUnsupported
    And the failure message names "ML-KEM-768"

  Scenario: An ML-KEM backend that runs without error but produces wrong output is caught
    # The harder case than an outright exception: a backend that
    # "succeeds" but is silently incorrect. Import success, or even a
    # clean function return, is not sufficient evidence the primitive
    # actually works.
    Given ML-KEM-768 decapsulation silently returns the wrong shared secret on this backend
    When I run the crypto backend check
    Then the check fails with CryptoBackendUnsupported
    And the failure message mentions mismatched shared secrets

  Scenario Outline: Each AEAD algorithm the backend check covers round-trips correctly
    When I encrypt "capability-check" under <algorithm>
    And I decrypt the resulting ciphertext under the same key
    Then the decrypted plaintext equals "capability-check"

    Examples:
      | algorithm         |
      | AES-256-GCM        |
      | ChaCha20-Poly1305   |

  Scenario: A broken AEAD primitive is caught, not silently ignored
    Given AES-256-GCM encryption is broken on this backend
    When I run the crypto backend check
    Then the check fails with CryptoBackendUnsupported
    And the failure message names "AES-256-GCM"

  Scenario: AES-128-GCM and AES-192-GCM are deliberately not checked
    # Unlike ML-KEM-512 (excluded because the library doesn't offer it),
    # AES-128-GCM and AES-192-GCM ARE available in the underlying
    # cryptography library -- they're excluded because this project
    # doesn't negotiate them (see bottom.py's AEAD_OIDS), so checking
    # them at startup would verify something that's never actually used.
    Then exactly AES-256-GCM and ChaCha20-Poly1305 are the AEAD algorithms the crypto backend check covers

  Scenario: HKDF-SHA256 derives a key of the requested length
    When I derive a 32-byte key with HKDF-SHA256
    Then the derived key is exactly 32 bytes long

  Scenario: The check stops at the first broken primitive rather than checking everything
    # check_backend() checks ML-KEM-768, then ML-KEM-1024, then
    # AES-256-GCM, then ChaCha20-Poly1305, then HKDF, in that order, and
    # does not catch-and-continue past a failure.
    Given ML-KEM-768 key generation is broken on this backend
    And AES-256-GCM encryption is also broken on this backend
    When I run the crypto backend check
    Then the check fails with CryptoBackendUnsupported
    And the failure message names "ML-KEM-768", not "AES-256-GCM"

  Scenario Outline: ML-KEM public key and ciphertext sizes match FIPS 203 Table 3
    # Cross-checked against kem_make.bottom's own length constants, so a
    # future cryptography release that changes these sizes is caught
    # here rather than only inside a live handshake.
    When I generate an ML-KEM-<level> key pair and encapsulate against it
    Then the raw public key is <public_key_bytes> bytes long
    And the ciphertext is <ciphertext_bytes> bytes long

    Examples:
      | level | public_key_bytes | ciphertext_bytes |
      | 768   | 1184              | 1088              |
      | 1024  | 1568              | 1568              |
