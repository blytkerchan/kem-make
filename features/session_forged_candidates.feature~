# Session sub-layer for KEM-MAKE
Feature: Rejecting forged and unauthenticated handshake messages
  As an implementer of KEM-MAKE
  I want every message that fails cryptographic confirmation to be
  rejected outright, with no PDU ever sent in response
  So that KEM encapsulation needing only a public key -- which anyone can
  obtain from the wire -- never lets a forged message be mistaken for a
  real one, even though it is structurally indistinguishable from a real
  one until the confirmation step

  Background:
    Given an initiator identity "alice" and a responder identity "bob", each knowing the other's public key
    And an initiator Session "alice_layer" for "alice" and a responder Session "bob_layer" for "bob"

  Scenario: A forged session-completion-request built with only public keys is rejected
    # Mallory can build a structurally valid SessionCompletionRequest
    # using nothing but Bob's ephemeral public key, which was sent in the
    # clear -- but cannot produce a c_m that decrypts under the real
    # session key, since that requires the actual shared secrets.
    Given "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s outgoing PDU
    When "bob_layer" receives a forged session-completion-request for the same correlation id, encrypted under an unrelated key
    Then processing that PDU fails with HandshakeFailed
    And "bob_layer" has no new PDU ready to send

  Scenario: A forged session-completion-response is rejected even though it is structurally valid
    Given "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s outgoing PDU
    And "alice_layer" receives "bob_layer"'s outgoing PDU
    When "alice_layer" receives a forged session-completion-response with an arbitrary h_m for the same correlation id
    Then processing that PDU fails with HandshakeFailed

  Scenario: A session-init-request claiming an identity the responder doesn't recognize is rejected
    Given a stranger identity "mallory" unknown to "bob"
    And an initiator Session "mallory_layer" for "mallory"
    When "mallory_layer" initiates a handshake with "bob"
    And "bob_layer" receives "mallory_layer"'s outgoing PDU
    Then processing that PDU fails with HandshakeFailed
    And "bob_layer" has no PDU ready to send

  Scenario: A handshake with no mutually acceptable AEAD algorithm is rejected
    Given "alice_layer" only accepts AEAD "aes256-gcm"
    And "bob_layer" only accepts AEAD "chacha20-poly1305"
    When "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s outgoing PDU
    Then processing that PDU fails with HandshakeFailed
    And "bob_layer" has no PDU ready to send

  Scenario: An unexpected PDU type for the current state is rejected
    Given "alice_layer" initiates a handshake with "bob"
    When "alice_layer" receives an established-session message PDU for the same correlation id
    Then processing that PDU fails with UnexpectedPDU
