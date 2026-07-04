Feature: Post-handshake application messages
  As an implementer of KEM-MAKE
  I want a Message PDU carrying a per-direction sequence number and an
  opaque payload
  So that application data exchanged after the handshake completes can be
  ordered per direction, using the independently derived session key for
  that direction to guarantee uniqueness rather than a per-message nonce

  Note: this feature covers the wire structure only. Sequence-number
  semantics such as monotonicity or gap handling are protocol-layer
  behaviour and are not enforced by the Message class itself -- "seq" is
  an unconstrained INTEGER as far as the ASN.1 structure is concerned.
  There is deliberately no nonce field on this PDU: each direction has its
  own session key derived via HKDF, so the pair (direction key, seq) is
  what must be unique, not seq alone.

  Background:
    Given application payload bytes "m_data"

  Scenario: A Message carries a sequence number and payload, both mandatory
    When I build a Message with seq=1 and m="m_data"
    Then the Message round-trips through DER encoding unchanged
    And its "seq" field equals 1
    And its "m" field equals "m_data"

  Scenario: A Message is not valid without a sequence number
    When I attempt to build a Message with only m="m_data" and no "seq"
    Then encoding the Message fails

  Scenario: A Message is not valid without a payload
    When I attempt to build a Message with only seq=1 and no "m"
    Then encoding the Message fails

  Scenario: A Message has no nonce field
    Given a built Message with seq=1 and m="m_data"
    Then the Message has exactly the fields "seq" and "m"

  Scenario: Sequence numbers are scoped per direction, not per session
    Given a Message sent from Alice to Bob with seq=5 and m="from alice"
    And a Message sent from Bob to Alice with seq=5 and m="from bob"
    Then both Messages are valid and independently encodable
    And their "seq" fields are equal
    And their DER encodings differ

  Scenario: Uniqueness comes from the per-direction session key, not from seq alone
    Given a Message sent from Alice to Bob with seq=5 and m="from alice"
    And a Message sent from Bob to Alice with seq=5 and m="from bob"
    Then nothing in the Message structure guarantees seq alone is unique across the session
    And the two Messages are only safely distinguishable because each direction uses its own session key

  Scenario: A Message is one of the tagged alternatives in MakePayload
    Given a built Message with seq=1 and m="m_data"
    When I wrap it in a MakeMessage payload
    Then the payload's chosen alternative name is "message"

  Scenario Outline: Sequence numbers of various magnitudes encode and decode correctly
    When I build a Message with seq=<seq> and m="m_data"
    Then the Message round-trips through DER encoding unchanged
    And its "seq" field equals <seq>

    Examples:
      | seq        |
      | 0          |
      | 1          |
      | 255        |
      | 4294967295 |

