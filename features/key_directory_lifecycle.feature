# Security sub-layer for KEM-MAKE
Feature: Key directory lifecycle
  As an implementer of KEM-MAKE
  I want a key directory whose master key is derived from a passphrase
  and never written to disk
  So that the passphrase is the only secret that must ever be protected,
  and a stolen key directory alone is useless without it

  Scenario: Creating a new key directory derives a master key without storing it
    Given a passphrase "correct horse battery staple"
    When I create a key directory at a fresh path with that passphrase
    Then the key directory is created successfully
    And no file anywhere under that path contains the raw master key bytes

  Scenario: The header stores only what's needed to re-derive the master key, never the key itself
    Given a passphrase "correct horse battery staple"
    When I create a key directory at a fresh path with that passphrase
    Then the header file contains exactly a version, a KDF salt, an iteration count, and a verification tag
    And the header file does not contain the raw master key bytes

  Scenario: Opening a key directory with the correct passphrase succeeds
    Given a key directory created with passphrase "correct horse battery staple"
    When I open that key directory with passphrase "correct horse battery staple"
    Then the key directory opens successfully

  Scenario: Opening a key directory with the wrong passphrase is rejected
    Given a key directory created with passphrase "correct horse battery staple"
    When I attempt to open that key directory with passphrase "wrong passphrase"
    Then opening the key directory fails with WrongPassphrase

  Scenario: The wrong-passphrase error does not reveal either passphrase
    Given a key directory created with passphrase "correct horse battery staple"
    When I attempt to open that key directory with passphrase "wrong passphrase"
    Then the resulting error message does not contain "correct horse battery staple"
    And the resulting error message does not contain "wrong passphrase"

  Scenario: Creating a key directory refuses a non-empty existing directory
    Given a directory that already contains an unrelated file
    When I attempt to create a key directory at that same path
    Then creating the key directory fails

  Scenario: Directories and files are created with restrictive permissions
    Given a key directory created with passphrase "pass"
    Then the key directory itself is readable and writable only by its owner
    And the public and private subdirectories are readable and writable only by their owner
    And the header file is readable and writable only by its owner

  Scenario Outline: The master key is never stored, regardless of passphrase or iteration count
    Given a passphrase "<passphrase>"
    When I create a key directory at a fresh path with that passphrase using <iterations> PBKDF2 iterations
    And I add a public key and a private key to it
    Then no file anywhere under that path contains the raw master key bytes

    Examples:
      | passphrase                                                                        | iterations |
      | correct horse battery staple                                                      | 100        |
      | a                                                                                  | 1          |
      | a much longer passphrase than the others, well over sixty-four bytes long overall  | 500        |
