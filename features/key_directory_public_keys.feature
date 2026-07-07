# Key store component for KEM-MAKE
Feature: Storing and retrieving public keys
  As an implementer of KEM-MAKE
  I want public keys stored in plaintext but identified by a cached KeyId
  So that anyone can read them without the passphrase, and looking a key
  up under any hash algorithm never costs more than one recomputation
  per algorithm, ever

  Background:
    Given a key directory created with passphrase "pass"
    And a valid ML-KEM-768 KemPublicKey "pk"

  Scenario: Adding a public key returns its primary SHA-256 KeyId
    When I add "pk" as a public key
    Then a KeyId is returned
    And that KeyId's hash algorithm is SHA-256

  Scenario: Adding the same public key twice is rejected
    Given "pk" has already been added as a public key
    When I attempt to add "pk" as a public key again
    Then adding the public key fails with DuplicateKey

  Scenario: Retrieving a public key by its primary KeyId returns it unchanged
    Given "pk" has already been added as a public key, with KeyId "kid"
    When I retrieve the public key for "kid"
    Then the retrieved key is byte-for-byte identical to "pk"

  Scenario: Looking up a KeyId that was never added fails
    Given a second valid ML-KEM-768 KemPublicKey "other_pk" that was never added
    When I compute the primary KeyId of "other_pk" without adding it
    And I attempt to retrieve the public key for that KeyId
    Then retrieving the public key fails with KeyNotFound

  Scenario: Public key files are stored in plaintext, not encrypted
    Given "pk" has already been added as a public key, with KeyId "kid"
    When I read the raw bytes of the public key file for "kid" directly from disk
    Then those raw bytes decode as a valid public key entry without needing the passphrase

  Scenario: Requesting a KeyId under a different digest computes and caches it
    Given "pk" has already been added as a public key, with KeyId "kid"
    When I request the KeyId for "kid" under digest "sha384"
    Then a KeyId with hash algorithm SHA-384 is returned
    And that computation is recorded so it is never repeated

  Scenario: Requesting an already-cached alternate digest does not recompute it
    Given "pk" has already been added as a public key, with KeyId "kid"
    And the SHA-384 KeyId for "kid" has already been computed once
    When I request the KeyId for "kid" under digest "sha384" again
    Then the same SHA-384 KeyId is returned
    And no new hash computation occurs

  Scenario: A cached alternate KeyId can retrieve the same public key directly
    Given "pk" has already been added as a public key, with KeyId "kid"
    And the SHA-384 KeyId for "kid" has already been computed once
    When I retrieve the public key using that SHA-384 KeyId directly
    Then the retrieved key is byte-for-byte identical to "pk"

  Scenario: Public key entries reject non-canonical DER encodings
    Given "pk" has already been added as a public key, with KeyId "kid"
    And the stored public key file for "kid" has been rewritten with a non-minimal-length BER encoding
    When I attempt to retrieve the public key for "kid"
    Then retrieving the public key fails with NonCanonicalEncoding
