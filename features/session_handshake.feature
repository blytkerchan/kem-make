# Bottom sub-layer for KEM-MAKE
Feature: KEM-MAKE handshake messages
  As an implementer of KEM-MAKE
  I want the four handshake PDUs to carry the fields the protocol defines,
  with SessionCompletionResponse's optional early-data field ("m") absent
  from the wire when unused
  So that peers who don't use the early-data optimization pay no encoding
  cost for it, peers who do use it can distinguish "absent" from "empty".

  Background:
    Given a valid ML-KEM-768 KemCiphertext "ct"
    And a valid ML-KEM-768 KemPublicKey "pk"
    And a KeyId "kid" built from "pk"
    And a second valid ML-KEM-768 KemPublicKey "pk_b"
    And a KeyId "kid_b" built from "pk_b"

  Scenario: A session-init-request carries a ciphertext, the recipient's key id, ephemeral public key, sender's key id, and acceptable AEAD list
    When I build a SessionInitRequest with ct1="ct", key_id_b="kid_b", pk_a_star="pk", key_id_a="kid", acceptable_aeads=["aes256-gcm", "chacha20-poly1305"]
    Then the SessionInitRequest round-trips through DER encoding unchanged
    And its acceptable_aeads field contains "aes256-gcm" and "chacha20-poly1305", in that order

  Scenario: key_id_b identifies the recipient key the ciphertext was encapsulated against
    Given a third valid ML-KEM-768 KemPublicKey "pk_b_other"
    And a KeyId "kid_b_other" built from "pk_b_other"
    When I build a SessionInitRequest with ct1="ct", key_id_b="kid_b", pk_a_star="pk", key_id_a="kid", acceptable_aeads=["aes256-gcm"]
    Then the SessionInitRequest's key_id_b matches "kid_b"
    And the SessionInitRequest's key_id_b does not match "kid_b_other"

  Scenario: A session-init-request cannot omit the recipient's key id
    When I attempt to build a SessionInitRequest with ct1="ct", pk_a_star="pk", key_id_a="kid", acceptable_aeads=["aes256-gcm"] and no key_id_b
    Then encoding the SessionInitRequest fails

  Scenario: A session-init-request cannot omit the acceptable AEAD list
    When I attempt to build a SessionInitRequest with ct1="ct", key_id_b="kid_b", pk_a_star="pk", key_id_a="kid" and no acceptable_aeads
    Then encoding the SessionInitRequest fails

  Scenario: The acceptable AEAD list must contain at least one algorithm
    When I attempt to build a SessionInitRequest with ct1="ct", key_id_b="kid_b", pk_a_star="pk", key_id_a="kid", acceptable_aeads=[]
    Then building the acceptable AEAD list fails

  Scenario: The acceptable AEAD list may include an algorithm this implementation doesn't recognize
    When I build a SessionInitRequest with ct1="ct", key_id_b="kid_b", pk_a_star="pk", key_id_a="kid", acceptable_aeads=["1.3.6.1.4.1.99999.1"]
    Then the SessionInitRequest round-trips through DER encoding unchanged

  Scenario: A session-init-response carries a key id, ephemeral public key, two ciphertexts, a nonce, and the chosen AEAD
    Given a second valid ML-KEM-768 KemCiphertext "ct2"
    And a nonce "nB" of 16 bytes
    When I build a SessionInitResponse with key_id_b="kid", pk_b_star="pk", ct2="ct", ct3="ct2", n_b="nB", chosen_aead="aes256-gcm"
    Then the SessionInitResponse round-trips through DER encoding unchanged
    And its chosen_aead field is "aes256-gcm"

  Scenario: A session-init-response cannot omit the chosen AEAD
    Given a second valid ML-KEM-768 KemCiphertext "ct2"
    And a nonce "nB" of 16 bytes
    When I attempt to build a SessionInitResponse with key_id_b="kid", pk_b_star="pk", ct2="ct", ct3="ct2", n_b="nB" and no chosen_aead
    Then encoding the SessionInitResponse fails

  Scenario: A session-completion-request's cM is itself the false-start payload
    Given a nonce "nA" of 16 bytes
    And an application ciphertext "cM" of 16 bytes
    When I build a SessionCompletionRequest with c_m="cM", ct4="ct", n_a="nA"
    Then the SessionCompletionRequest has exactly the fields "c_m", "ct4", and "n_a"
    And it has no separate "m" field, since cM already carries the false-start payload

  Scenario: A session-completion-response without early data omits the "m" field from the wire
    Given a MAC value "hM" of 32 bytes
    When I build a SessionCompletionResponse with h_m="hM" and no "m"
    Then the encoded SessionCompletionResponse, when loaded, has an absent "m" field
    And the encoded SessionCompletionResponse is shorter than the same message with "m" present

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
