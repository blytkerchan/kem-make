# Security sub-layer for KEM-MAKE
Feature: Storing and retrieving private keys
  As an implementer of KEM-MAKE
  I want private keys wrapped with AES-256 Key Wrap with Padding under a
  key-encrypting key that's independently derived for every private key
  So that compromising one private key's KEK reveals nothing about any
  other key's, and tampering with a wrapped key is caught before its
  bytes are ever returned

  Background:
    Given a key directory created with passphrase "pass"
    And a valid ML-KEM-768 KemPublicKey "pk"
    And "pk" has already been added as a public key, with KeyId "kid"

  Scenario: A private key cannot be added before its public key is registered
    Given a second valid ML-KEM-768 KemPublicKey "unregistered_pk" that was never added
    When I attempt to add private key bytes for "unregistered_pk"
    Then adding the private key fails with PrivateKeyRequiresPublicKey

  Scenario: Adding a private key succeeds once its public key is registered
    When I add private key bytes "secret-key-material-32-bytes!!!" for "pk"
    Then the private key is added successfully

  Scenario: Adding the same private key twice is rejected
    Given private key bytes have already been added for "pk"
    When I attempt to add private key bytes for "pk" again
    Then adding the private key fails with DuplicateKey

  Scenario: Retrieving a private key returns the original bytes unchanged
    Given private key bytes "secret-key-material-32-bytes!!!" have already been added for "pk"
    When I retrieve the private key for "kid"
    Then the retrieved bytes equal "secret-key-material-32-bytes!!!"

  Scenario: Looking up a private key that was never added fails
    When I attempt to retrieve the private key for "kid"
    Then retrieving the private key fails with KeyNotFound

  Scenario: Each private key gets its own independently salted key-encrypting key
    Given a second valid ML-KEM-768 KemPublicKey "pk2", added as a public key with KeyId "kid2"
    When I add private key bytes for "pk" and separately for "pk2"
    Then the two stored entries have different key-encrypting-key salts
    And both private keys still decrypt correctly and independently of one another

  Scenario: Private keys are wrapped with AES Key Wrap, not an AEAD
    Given private key bytes have already been added for "pk"
    When I inspect the stored private key entry's fields for "kid"
    Then the entry has a key-encrypting-key salt, a wrap algorithm identifier, and a wrapped key
    And the entry has no nonce field

  Scenario: Tampering with a stored wrapped private key is detected on retrieval
    Given private key bytes have already been added for "pk"
    And a byte in the stored wrapped private key for "kid" has been flipped
    When I attempt to retrieve the private key for "kid"
    Then retrieving the private key fails with PrivateKeyUnwrapFailed

  Scenario: Private key entries reject non-canonical DER encodings
    Given private key bytes have already been added for "pk"
    And the stored private key file for "kid" has been rewritten with a non-minimal-length BER encoding
    When I attempt to retrieve the private key for "kid"
    Then retrieving the private key fails with NonCanonicalEncoding
