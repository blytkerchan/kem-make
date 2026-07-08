# Key store component for KEM-MAKE
Feature: Integrity protection against on-disk tampering
  As an implementer of KEM-MAKE
  I want every stored public key entry, and the alternate-hash index that
  points to them, protected by a MAC that is actually checked before any
  lookup result is trusted
  So that someone with filesystem write access cannot substitute a
  different key for the one a caller asked for, whether by editing an
  entry directly, swapping two entries' filenames, or redirecting the
  alternate-hash index at a different, individually valid entry

  Background:
    Given a key directory created with passphrase "pass"
    And a valid ML-KEM-768 KemPublicKey "pk_bob", added as a public key with KeyId "kid_bob"
    And a second valid ML-KEM-768 KemPublicKey "pk_attacker", added as a public key with KeyId "kid_attacker"

  Scenario: Editing a stored public key's content in place is detected
    Given the stored public key data for "kid_bob" has been replaced with "pk_attacker", leaving the original integrity tag in place
    When I attempt to retrieve the public key for "kid_bob"
    Then retrieving the public key fails with PublicKeyIntegrityError

  Scenario: Editing a stored public key's integrity tag directly is detected
    Given a byte in the stored integrity tag for "kid_bob" has been flipped
    When I attempt to retrieve the public key for "kid_bob"
    Then retrieving the public key fails with PublicKeyIntegrityError

  Scenario: Swapping two validly-tagged public key entries is detected for the first entry
    Given the on-disk files for "kid_bob" and "kid_attacker" have had their contents swapped
    When I attempt to retrieve the public key for "kid_bob"
    Then retrieving the public key fails with PublicKeyIntegrityError

  Scenario: Swapping two validly-tagged public key entries is detected for the second entry
    Given the on-disk files for "kid_bob" and "kid_attacker" have had their contents swapped
    When I attempt to retrieve the public key for "kid_attacker"
    Then retrieving the public key fails with PublicKeyIntegrityError

  Scenario: The alternate-hash index is itself integrity-protected
    Given the SHA-384 KeyId for "kid_bob" has already been computed once
    And a byte in the alternate-hash index's integrity tag has been flipped
    When I attempt to retrieve the public key using that SHA-384 KeyId
    Then retrieving the public key fails with AltIndexIntegrityError

  Scenario: Redirecting the alternate-hash index to a different, individually valid entry is rejected
    Given the SHA-384 KeyId for "kid_bob" has already been computed once
    And the alternate-hash index has been re-signed to map that SHA-384 KeyId to "kid_attacker" instead
    When I attempt to retrieve the public key using that SHA-384 KeyId
    Then retrieving the public key fails with KeyNotFound
    And "pk_attacker" is never returned as the result

  Scenario: Key ID comparisons during lookup use constant-time comparison
    # KeyId identifies a *public* key and isn't secret the way a password
    # or KEK is, but this codebase treats every digest/hash comparison as
    # constant-time by policy regardless of whether a specific instance
    # is provably exploitable -- it's free, and it removes "is this
    # actually exploitable" from ever needing to be re-argued later.
    When I retrieve the public key for "kid_bob"
    Then the key_hash comparison performed during that lookup used a constant-time comparison function, not `==`
