Feature: Post-handshake application messages
  As an implementer of KEM-MAKE
  I want a Message PDU carrying a per-direction sequence number, a nonce,
  and an opaque payload
  So that application data exchanged after the handshake completes can be
  ordered per direction, and every message has a value that is genuinely
  unique across the whole session even though the sequence number alone
  is not

  Note: this feature covers the wire structure only. Sequence-number
  semantics such as monotonicity or gap handling are protocol-layer
  behaviour and are not enforced by the Message class itself -- "seq" is
  an unconstrained INTEGER as far as the ASN.1 structure is concerned.

  Background:
    Given application payload bytes "m_data"
    And a 12-byte nonce "n_data"

  Scenario: A Message carries a sequence number, nonce, and payload, all mandatory
    When I build a Message with seq=1, n="n_data", m="m_data"
    Then the Message round-trips through DER encoding unchanged
    And its "seq" field equals 1
    And its "n" field equals "n_data"
    And its "m" field equals "m_data"

  Scenario: A Message is not valid without a sequence number
    When I attempt to build a Message with only n="n_data" and m="m_data"
    Then encoding the Message fails

  Scenario: A Message is not valid without a nonce
    When I attempt to build a Message with only seq=1 and m="m_data"
    Then encoding the Message fails

  Scenario: A Message is not valid without a payload
    When I attempt to build a Message with only seq=1 and n="n_data"
    Then encoding the Message fails

  Scenario: Sequence numbers are scoped per direction, not per session
    Given a Message sent from Alice to Bob with seq=5, a nonce "n_alice", and m="from alice"
    And a Message sent from Bob to Alice with seq=5, a nonce "n_bob", and m="from bob"
    Then both Messages are valid and independently encodable
    And their "seq" fields are equal
    And their DER encodings differ

  Scenario: The nonce, not the sequence number, is what must be relied on for uniqueness
    Given a Message sent from Alice to Bob with seq=5, a nonce "n_alice", and m="from alice"
    And a Message sent from Bob to Alice with seq=5, a nonce "n_bob", and m="from bob"
    Then "n_alice" and "n_bob" are different values
    And nothing in the Message structure guarantees seq alone is unique across the session

  Scenario: A Message is one of the tagged alternatives in MakePayload
    Given a built Message with seq=1, n="n_data", m="m_data"
    When I wrap it in a MakeMessage payload
    Then the payload's chosen alternative name is "message"

  Scenario Outline: Sequence numbers of various magnitudes encode and decode correctly
    When I build a Message with seq=<seq>, n="n_data", m="m_data"
    Then the Message round-trips through DER encoding unchanged
    And its "seq" field equals <seq>

    Examples:
      | seq        |
      | 0          |
      | 1          |
      | 255        |
      | 4294967295 |

