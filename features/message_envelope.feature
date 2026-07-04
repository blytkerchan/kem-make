Feature: Session message envelope
  As an implementer of KEM-MAKE
  I want every PDU wrapped in a versioned envelope carrying a correlation id
  So that peers can multiplex concurrent sessions and evolve the protocol
  version without breaking existing decoders

  Background:
    Given a built SessionCompletionResponse "scr" with h_m of 32 bytes and no "m"

  Scenario: The default protocol version is omitted from the DER encoding
    Given a random correlation id "cid"
    When I build a MakeMessage with cid="cid", payload="scr", version=0
    Then the encoded MakeMessage does not contain an explicit version field
    And loading the encoded MakeMessage reports its version as 0

  Scenario: A non-default protocol version is encoded explicitly
    Given a random correlation id "cid"
    When I build a MakeMessage with cid="cid", payload="scr", version=1
    Then the encoded MakeMessage contains an explicit version field
    And it is longer than the equivalent message with version=0

  Scenario: The correlation id must be exactly 128 bits
    Given a correlation id "short_cid" of 8 bytes
    When I attempt to load a MakeMessage whose cid is "short_cid"
    Then an InvalidCorrelationId error is raised

  Scenario: A correctly sized correlation id round-trips as a UUID
    Given a random correlation id "cid"
    When I build a MakeMessage with cid="cid", payload="scr", version=0
    And I load the resulting encoding
    Then the loaded message's correlation_id equals "cid"

  Scenario: A canonical DER encoding is accepted
    Given a random correlation id "cid"
    When I build a MakeMessage with cid="cid", payload="scr", version=0
    Then loading its DER encoding succeeds

  Scenario: A non-minimal-length BER encoding is rejected even though it parses
    Given a random correlation id "cid"
    And a MakeMessage with cid="cid", payload="scr", version=0
    And that message re-encoded with a non-minimal-length BER length field
    When I load the non-canonical encoding
    Then a NonCanonicalEncoding error is raised

  Scenario: An indefinite-length BER encoding is rejected outright
    Given a random correlation id "cid"
    And a MakeMessage with cid="cid", payload="scr", version=0
    And that message re-encoded with an indefinite-length form
    When I attempt to load the indefinite-length encoding
    Then loading fails

  Scenario Outline: Each envelope carries exactly one payload alternative
    Given a built <pdu>
    When I build a MakeMessage wrapping that <pdu> as its payload
    And I load the resulting encoding
    Then the loaded payload's chosen alternative name is "<alternative>"

    Examples:
      | pdu                          | alternative                    |
      | SessionInitRequest           | session_init_request           |
      | SessionInitResponse          | session_init_response          |
      | SessionCompletionRequest     | session_completion_request     |
      | SessionCompletionResponse    | session_completion_response    |
      | Message                      | message                        |
