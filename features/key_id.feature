# Security sub-layer for KEM-MAKE
Feature: Key identifier computation
  As an implementer of KEM-MAKE
  I want a KeyId to be a hash of the whole KemPublicKey structure, not just
  the raw key bytes
  So that the algorithm a key was declared under is bound into its
  identifier and cannot be silently swapped

  Background:
    Given a valid ML-KEM-768 KemPublicKey "pkA"

  Scenario: A KeyId is the digest of the DER encoding of the whole KemPublicKey
    When I build a KeyId for "pkA" using digest algorithm "sha256"
    Then the KeyId's key_hash equals the sha256 digest of the DER encoding of "pkA"
    And the KeyId's hash_algorithm is "sha256"

  Scenario: A KeyId is not simply the digest of the raw public key bytes
    When I build a KeyId for "pkA" using digest algorithm "sha256"
    Then the KeyId's key_hash does not equal the sha256 digest of the raw public key bytes of "pkA"

  Scenario: The same key bytes under a different declared algorithm produce a different KeyId
    Given the same raw public key bytes as "pkA" re-labelled as ML-KEM-1024, called "pkA_relabelled"
    When I build a KeyId for "pkA" using digest algorithm "sha256"
    And I build a KeyId for "pkA_relabelled" using digest algorithm "sha256"
    Then the two KeyIds are not equal

  Scenario: The hash_algorithm field describes how the KeyId was computed, not the key's KEM algorithm
    When I build a KeyId for "pkA" using digest algorithm "sha256"
    Then the KeyId's hash_algorithm does not indicate the ML-KEM level of "pkA"
