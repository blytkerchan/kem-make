Feature: KEM public key and ciphertext validation
  As an implementer of KEM-MAKE
  I want KemPublicKey and KemCiphertext to enforce ML-KEM algorithm
  identifiers and fixed lengths on both the build and load paths
  So that malformed or spoofed key material is rejected before it reaches
  the KEM operations themselves

  Background:
    Given the ML-KEM AlgorithmIdentifier OIDs from RFC 9935
    And the ML-KEM public key and ciphertext lengths from FIPS 203 Table 3

  Scenario Outline: Building a public key with correctly sized key bytes succeeds
    Given <length> bytes of public key material for ML-KEM-<level>
    When I build a KemPublicKey at level <level> from that key material
    Then the KemPublicKey is built successfully
    And its algorithm OID is "<oid>"
    And its parameters field is absent, not NULL

    Examples:
      | level | length | oid                      |
      | 512   | 800    | 2.16.840.1.101.3.4.4.1   |
      | 768   | 1184   | 2.16.840.1.101.3.4.4.2   |
      | 1024  | 1568   | 2.16.840.1.101.3.4.4.3   |

  Scenario Outline: Building a ciphertext with correctly sized bytes succeeds
    Given <length> bytes of ciphertext material for ML-KEM-<level>
    When I build a KemCiphertext at level <level> from that ciphertext material
    Then the KemCiphertext is built successfully
    And its algorithm OID is "<oid>"

    Examples:
      | level | length | oid                      |
      | 512   | 768    | 2.16.840.1.101.3.4.4.1   |
      | 768   | 1088   | 2.16.840.1.101.3.4.4.2   |
      | 1024  | 1568   | 2.16.840.1.101.3.4.4.3   |

  Scenario: Building a public key with the wrong number of bytes is rejected
    Given 1183 bytes of public key material for ML-KEM-768
    When I attempt to build a KemPublicKey at level 768 from that key material
    Then a KemLengthMismatch error is raised

  Scenario: Building a ciphertext with the wrong number of bytes is rejected
    Given 1089 bytes of ciphertext material for ML-KEM-768
    When I attempt to build a KemCiphertext at level 768 from that ciphertext material
    Then a KemLengthMismatch error is raised

  Scenario: Building a public key at an unsupported level is rejected
    When I attempt to build a KemPublicKey at level 999
    Then an UnknownKemAlgorithm error is raised

  Scenario: Loading a public key whose OID is not a recognized ML-KEM algorithm is rejected
    Given a DER-encoded KemPublicKey whose algorithm OID is "1.2.3.4.5"
    When I load that KemPublicKey
    Then an UnknownKemAlgorithm error is raised

  Scenario: Loading a public key whose declared algorithm and byte length disagree is rejected
    Given a valid ML-KEM-768 KemPublicKey
    And its public key bytes are truncated by one byte before encoding
    When I load that KemPublicKey
    Then a KemLengthMismatch error is raised
