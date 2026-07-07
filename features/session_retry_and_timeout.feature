# Session sub-layer for KEM-MAKE
Feature: Retry, timeout, and duplicate-PDU handling
  As an implementer of KEM-MAKE
  I want a lost reply to be handled by resending the EXACT bytes already
  sent, never regenerated ones, and I want a duplicate incoming PDU to
  produce the exact same reply without re-running any handshake logic
  So that retrying never diverges from what a peer already derived (fresh
  ephemeral keys on retry would silently break the handshake), and
  "same PDU in, same PDU out" holds as a real guarantee rather than
  usually holding

  Background:
    Given an initiator identity "alice" and a responder identity "bob", each knowing the other's public key
    And a SessionConfig with 2 max retries, a 5 second retry interval, and a 20 second TTL
    And an initiator SessionLayer "alice_layer" for "alice" using that config

  Scenario: A timeout before any reply resends the exact same PDU bytes
    Given "alice_layer" initiates a handshake with "bob" at time 0
    When time advances to 100 and "alice_layer" is updated
    Then "alice_layer" has a PDU ready to send
    And that PDU is byte-for-byte identical to the one originally sent

  Scenario: Exhausting the retry budget drops the session
    Given "alice_layer" initiates a handshake with "bob" at time 0
    When "alice_layer" times out and retries 2 times
    And "alice_layer" times out once more
    Then "alice_layer" is in state "dropped"
    And "alice_layer" has no PDU ready to send

  Scenario: Dropping a session never produces an outgoing PDU
    # No wire-level error message exists anywhere in this protocol --
    # exhausting retries must be silent, not signaled to the peer.
    Given "alice_layer" initiates a handshake with "bob" at time 0
    When "alice_layer" times out and retries 2 times
    And "alice_layer" times out once more
    Then at no point during that timeout sequence did dropping produce a PDU

  Scenario: A byte-identical duplicate incoming PDU produces the exact same reply
    Given a responder SessionLayer "bob_layer" for "bob"
    And "alice_layer" initiates a handshake with "bob"
    When "bob_layer" receives "alice_layer"'s outgoing PDU
    And "bob_layer" receives the exact same PDU bytes again
    Then "bob_layer"'s two replies are byte-for-byte identical

  Scenario: Processing a duplicate PDU does not regenerate ephemeral key material
    Given a responder SessionLayer "bob_layer" for "bob"
    And "alice_layer" initiates a handshake with "bob"
    When "bob_layer" receives "alice_layer"'s outgoing PDU
    And "bob_layer" receives the exact same PDU bytes again
    Then "bob_layer" is still in state "expect_session_completion_request"
    And "bob_layer"'s ephemeral key material is unchanged from the first time

  Scenario: The responder never retries -- its deadline is a pure TTL
    Given a responder SessionLayer "bob_layer" for "bob" using that config
    And "alice_layer" initiates a handshake with "bob" at time 0
    And "bob_layer" receives "alice_layer"'s outgoing PDU at time 0
    When time advances past the TTL and "bob_layer" is updated
    Then "bob_layer" is in state "dropped"
    And "bob_layer" never produced a resend of its own session-init-response
