Feature: KEM-MAKE handshake messages
  As an implementer of KEM-MAKE
  I want the four handshake PDUs to carry the fields the protocol defines,
  with the optional early-data field ("m") absent from the wire when unused
  So that peers who don't use the early-data optimization pay no encoding
  cost for it, and peers who do use it can distinguish "absent" from "empty"

  Background:
    Given a valid ML-KEM-768 KemCiphertext "ct"
    And a valid ML-KEM-768 KemPublicKey "pk"
    And a KeyId "kid" built from "pk"

  Scenario: A session-init-request carries a ciphertext, ephemeral public key, and key id
    When I build a SessionInitRequest with ct1="ct", pk_a_star="pk", key_id_a="kid"
    Then the SessionInitRequest round-trips through DER encoding unchanged

  Scenario: A session-init-response carries a key id, ephemeral public key, two ciphertexts, and a nonce
    Given a second valid ML-KEM-768 KemCiphertext "ct2"
    And a nonce "nB" of 16 bytes
    When I build a SessionInitResponse with key_id_b="kid", pk_b_star="pk", ct2="ct", ct3="ct2", n_b="nB"
    Then the SessionInitResponse round-trips through DER encoding unchanged

  Scenario: A session-completion-request without early data omits the "m" field from the wire
    Given a nonce "nA" of 16 bytes
    And an application ciphertext "cM" of 16 bytes
    When I build a SessionCompletionRequest with c_m="cM", ct4="ct", n_a="nA" and no "m"
    Then the encoded SessionCompletionRequest, when loaded, has an absent "m" field
    And the encoded SessionCompletionRequest is shorter than the same message with "m" present

  Scenario: A session-completion-request with early data carries "m" explicitly
    Given a nonce "nA" of 16 bytes
    And an application ciphertext "cM" of 16 bytes
    And early-data bytes "m_data"
    When I build a SessionCompletionRequest with c_m="cM", ct4="ct", n_a="nA" and m="m_data"
    Then the encoded SessionCompletionRequest, when loaded, has "m" equal to "m_data"

  Scenario: A session-completion-response without early data omits the "m" field from the wire
    Given a MAC value "hM" of 32 bytes
    When I build a SessionCompletionResponse with h_m="hM" and no "m"
    Then the encoded SessionCompletionResponse, when loaded, has an absent "m" field

  Scenario: A session-completion-response with early data carries "m" explicitly
    Given a MAC value "hM" of 32 bytes
    And early-data bytes "m_data"
    When I build a SessionCompletionResponse with h_m="hM" and m="m_data"
    Then the encoded SessionCompletionResponse, when loaded, has "m" equal to "m_data"

  Scenario Outline: Each handshake PDU carries its own implicit tag in MakePayload
    Given a built <pdu>
    When I wrap it in a MakeMessage payload
    Then the payload's chosen alternative name is "<alternative>"

    Examples:
      | pdu                          | alternative                    |
      | SessionInitRequest           | session_init_request           |
      | SessionInitResponse          | session_init_response          |
      | SessionCompletionRequest     | session_completion_request     |
      | SessionCompletionResponse    | session_completion_response    |
