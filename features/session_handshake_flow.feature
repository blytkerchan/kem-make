# Session sub-layer for KEM-MAKE
Feature: Establishing a KEM-MAKE session
  As an implementer of KEM-MAKE
  I want the session layer to run the full mutually-authenticated
  handshake as a push-in/pull-out/crank state machine, with no callbacks
  and no transport awareness
  So that the same session layer works over any transport, and every
  state transition is directly testable without I/O

  Background:
    Given an initiator identity "alice" and a responder identity "bob", each knowing the other's public key
    And an initiator SessionLayer "alice_layer" for "alice" and a responder SessionLayer "bob_layer" for "bob"

  Scenario: Initiating a handshake produces a session-init-request and no session id until then
    When "alice_layer" initiates a handshake with "bob"
    Then "alice_layer" is in state "expect_session_init_response"
    And "alice_layer" has a PDU ready to send
    And the ready PDU is a session_init_request

  Scenario: The full handshake establishes a session on both sides
    When "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    Then "alice_layer" is in state "established"
    And "bob_layer" is in state "established"

  Scenario: Both sides derive identical directional session keys
    Given "alice_layer" and "bob_layer" have completed a full handshake
    Then "alice_layer"'s and "bob_layer"'s derived session keys are identical in both directions

  Scenario: Both sides agree on the same correlation id throughout
    Given "alice_layer" and "bob_layer" have completed a full handshake
    Then "alice_layer"'s correlation id equals "bob_layer"'s correlation id

  Scenario: A false-start payload from the initiator is delivered to the responder
    When "alice_layer" queues payload "hello from alice" before initiating
    And "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    Then "bob_layer" has a payload ready
    And that payload is "hello from alice"

  Scenario: A false-start reply from the responder is delivered to the initiator
    Given "alice_layer" initiates a handshake with "bob"
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    When "bob_layer" queues payload "hello from bob" before processing the completion request
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    Then "alice_layer" has a payload ready
    And that payload is "hello from bob"

  Scenario: Established application traffic flows from the initiator to the responder
    Given "alice_layer" and "bob_layer" have completed a full handshake
    When "alice_layer" queues payload "message one" for the established session
    And "bob_layer" receives "alice_layer"'s next outgoing PDU
    Then "bob_layer" has a payload ready
    And that payload is "message one"

  Scenario: Established application traffic flows from the responder to the initiator
    Given "alice_layer" and "bob_layer" have completed a full handshake
    When "bob_layer" queues payload "message one" for the established session
    And "alice_layer" receives "bob_layer"'s next outgoing PDU
    Then "alice_layer" has a payload ready
    And that payload is "message one"

  Scenario: Established application traffic uses strictly increasing sequence numbers per direction
    Given "alice_layer" and "bob_layer" have completed a full handshake
    When "alice_layer" sends 3 established messages to "bob_layer"
    Then all 3 messages are delivered to "bob_layer" in order
