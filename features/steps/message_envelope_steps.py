from behave import when, then, given
from behave.api.pending_step import StepNotImplementedError

from kem_make import bottom, common
from kem_make.session import Role, Session

import uuid


@given(u'a built SessionCompletionResponse "scr" with h_m of 32 bytes and no "m"')
def step_impl(context):
    context.scr = bottom.SessionCompletionResponse({"h_m": b"\x00" * 32})


@given(u'a random correlation id "cid"')
def step_impl(context):
    context.cid = uuid.uuid4()


@when(u'I build a MakeMessage with cid="cid", payload="scr", version=0')
def step_impl(context):
    message = bottom.MakeMessage.build(context.cid, "session_completion_response", context.scr, version=0)
    context.message = message


@then(u'the encoded MakeMessage does not contain an explicit version field')
def step_impl(context):
    encoded_message = bytearray(context.message.dump())
    assert len(encoded_message) == 56
    # write to a file for debugging
    assert encoded_message[0:4] == b"\x30\x36\x04\x10" 
    # the next 16 bytes are the cid
    assert encoded_message[4:20] == context.cid.bytes
    assert encoded_message[20:24] == b"\xa3\x22\x04\x20" # the next 32 bytes are the h_m
    assert encoded_message[24:56] == b"\x00" * 32


@then(u'loading the encoded MakeMessage reports its version as 0')
def step_impl(context):
    loaded_message = bottom.MakeMessage.load(context.message.dump())
    assert loaded_message["version"].native == 0


@when(u'I build a MakeMessage with cid="cid", payload="scr", version=1')
def step_impl(context):
    message = bottom.MakeMessage.build(context.cid, "session_completion_response", context.scr, version=1)
    context.message = message


@then(u'the encoded MakeMessage contains an explicit version field')
def step_impl(context):
    encoded_message = bytearray(context.message.dump())
    assert encoded_message[0:7] == b"\x30\x39\x02\x01\x01\x04\x10" 


@then(u'it is longer than the equivalent message with version=0')
def step_impl(context):
    encoded_message = bytearray(context.message.dump())
    assert len(encoded_message) == 59 # the other one was 56 bytes


@given(u'a correlation id "short_cid" of 8 bytes')
def step_impl(context):
    context.cid = bytes=b"\x00" * 8


@when(u'I attempt to load a MakeMessage whose cid is "short_cid"')
def step_impl(context):
    try:
        bottom.MakeMessage.load(b"\x30\x2e\x04\x08" + context.cid + b"\xa3\x22\x04\x20" + b"\x00" * 32)
    except Exception as e:
        context.exception = e
        raised = True
    else:
        raised = False
    assert raised, "Expected an exception to be raised when loading a MakeMessage with a short correlation id"


@then(u'an InvalidCorrelationId error is raised')
def step_impl(context):
    assert isinstance(context.exception, bottom.InvalidCorrelationId), f"Expected InvalidCorrelationId error, but got {type(context.exception)}"


@when(u'I load the resulting encoding')
def step_impl(context):
    der_encoded = context.message.dump()
    loaded_message = bottom.MakeMessage.load(der_encoded)
    context.loaded_message = loaded_message


@then(u'the loaded message\'s correlation_id equals "cid"')
def step_impl(context):
    assert context.loaded_message["cid"].native == context.cid.bytes


@then(u'loading its DER encoding succeeds')
def step_impl(context):
    der_encoded = context.message.dump()
    loaded_message = bottom.MakeMessage.load(der_encoded)


@given(u'a MakeMessage with cid="cid", payload="scr", version=0')
def step_impl(context):
    message = bottom.MakeMessage.build(context.cid, "session_completion_response", context.scr, version=0)
    context.message = message


@given(u'that message re-encoded with a non-minimal-length BER length field')
def step_impl(context):
    canonical_encoding = bytearray(context.message.dump())
    # Modify the length field to be non-minimal
    non_canonical_encoding = canonical_encoding[:1] + b'\x81' + canonical_encoding[1:]
    context.non_canonical_encoding = non_canonical_encoding


@when(u'I load the non-canonical encoding')
def step_impl(context):
    try:
        loaded_message = bottom.MakeMessage.load(bytes(context.non_canonical_encoding))
    except Exception as e:
        context.exception = e
        raised = True
    else:
        raised = False
    assert raised, "Expected an exception to be raised when loading a non-canonical encoding"


@then(u'a NonCanonicalEncoding error is raised')
def step_impl(context):
    assert isinstance(context.exception, common.NonCanonicalEncoding), f"Expected NonCanonicalEncoding error, but got {type(context.exception)}"


@given(u'that message re-encoded with an indefinite-length form')
def step_impl(context):
    indefinite_length_encoding = bytearray(context.message.dump())
    # Modify the length field to be non-minimal
    indefinite_length_encoding[1] = 0x80
    for _ in range(2):
        indefinite_length_encoding.append(0x00)  # Append a zero byte to indicate indefinite length
    context.indefinite_length_encoding = indefinite_length_encoding


@when(u'I attempt to load the indefinite-length encoding')
def step_impl(context):
    try:
        loaded_message = bottom.MakeMessage.load(bytes(context.indefinite_length_encoding))
    except Exception as e:
        context.exception = e
        context.load_failed = True
    else:
        context.load_failed = False


@then(u'loading fails')
def step_impl(context):
    assert context.load_failed, "Expected an exception to be raised when loading an indefinite-length encoding"


@given(u'a built SessionInitRequest')
def step_impl(context):
    ct1_algorithm_identifier = bottom.AlgorithmIdentifier({"algorithm": "1.2.3.4.5"})
    ct1 = bottom.KemCiphertext({ "algorithm": ct1_algorithm_identifier, "ciphertext": b"\x00" * 32 })
    hash_algorithm = bottom.DigestAlgorithm({"algorithm": "1.2.3.4.5"})
    key_id_b = bottom.KeyId({"hash_algorithm": hash_algorithm, "key_hash": b"\x00" * 16})
    pk_a_star = bottom.KemPublicKey({"algorithm": ct1_algorithm_identifier, "public_key": b"\x00" * 32})
    key_id_a = bottom.KeyId({"hash_algorithm": hash_algorithm, "key_hash": b"\x00" * 16})
    acceptable_aeads = bottom.AeadAlgorithmList.build(["2.16.840.1.101.3.4.1.46"])
    
    session_init_request = bottom.SessionInitRequest({
        "ct1": ct1,
        "key_id_b": key_id_b,
        "pk_a_star": pk_a_star,
        "key_id_a": key_id_a,
        "acceptable_aeads": acceptable_aeads,
        })
    context.session_init_request = session_init_request


@when(u'I build a MakeMessage wrapping that SessionInitRequest as its payload')
def step_impl(context):
    payload = bottom.MakePayload("session_init_request", context.session_init_request)
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": payload})


@then(u'the loaded payload\'s chosen alternative name is "session_init_request"')
def step_impl(context):
    assert context.message["payload"].name == "session_init_request", f"Expected chosen alternative name to be 'session_init_request', but got {context.message['payload'].name}"


@given(u'a built SessionInitResponse')
def step_impl(context):
    hash_algorithm = bottom.DigestAlgorithm({"algorithm": "1.2.3.4.5"})
    ct2_algorithm_identifier = bottom.AlgorithmIdentifier({"algorithm": "1.2.3.4.5"})
    pk_b_star = bottom.KemPublicKey({"algorithm": ct2_algorithm_identifier, "public_key": b"\x00" * 32})
    ct2 = bottom.KemCiphertext({ "algorithm": ct2_algorithm_identifier, "ciphertext": b"\x00" * 32 })
    ct3 = bottom.KemCiphertext({ "algorithm": ct2_algorithm_identifier, "ciphertext": b"\x00" * 32 })
    n_b = b"\x00" * 4
    chosen_aead = "2.16.840.1.101.3.4.1.46"
    context.session_init_response = bottom.SessionInitResponse({
        "pk_b_star": pk_b_star,
        "ct2": ct2,
        "ct3": ct3,
        "n_b": n_b,
        "chosen_aead": chosen_aead
    })


@when(u'I build a MakeMessage wrapping that SessionInitResponse as its payload')
def step_impl(context):
    payload = bottom.MakePayload("session_init_response", context.session_init_response)
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": payload})


@then(u'the loaded payload\'s chosen alternative name is "session_init_response"')
def step_impl(context):
    assert context.loaded_message["payload"].name == "session_init_response", f"Expected chosen alternative name to be 'session_init_response', but got {context.loaded_message['payload'].name}"


@given(u'a built SessionCompletionRequest')
def step_impl(context):
    ct4_algorithm_identifier = bottom.AlgorithmIdentifier({"algorithm": "1.2.3.4.5"})
    ct4 = bottom.KemCiphertext({ "algorithm": ct4_algorithm_identifier, "ciphertext": b"\x00" * 32 })
    context.session_completion_request = bottom.SessionCompletionRequest({"c_m": b"\x00" * 32, "n_a": b"\x00" * 16, "ct4": ct4})


@when(u'I build a MakeMessage wrapping that SessionCompletionRequest as its payload')
def step_impl(context):
    payload = bottom.MakePayload("session_completion_request", context.session_completion_request)
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": payload})


@then(u'the loaded payload\'s chosen alternative name is "session_completion_request"')
def step_impl(context):
    assert context.loaded_message["payload"].name == "session_completion_request", f"Expected chosen alternative name to be 'session_completion_request', but got {context.loaded_message['payload'].name}"


@given(u'a built SessionCompletionResponse')
def step_impl(context):
    pass # The SessionCompletionResponse is already built in a previous step, so we don't need to do anything here.


@when(u'I build a MakeMessage wrapping that SessionCompletionResponse as its payload')
def step_impl(context):
    payload = bottom.MakePayload("session_completion_response", context.scr)
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": payload})


@then(u'the loaded payload\'s chosen alternative name is "session_completion_response"')
def step_impl(context):
    assert context.loaded_message["payload"].name == "session_completion_response", f"Expected chosen alternative name to be 'session_completion_response', but got {context.loaded_message['payload'].name}"


@given(u'a built Message')
def step_impl(context):
    message = bottom.Message({ "seq": 1, "m": b"\x00" * 32 })
    context.msg = message


@when(u'I build a MakeMessage wrapping that Message as its payload')
def step_impl(context):
    payload = bottom.MakePayload("message", context.msg)
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": payload})


@then(u'the loaded payload\'s chosen alternative name is "message"')
def step_impl(context):
    assert context.loaded_message["payload"].name == "message", f"Expected chosen alternative name to be 'message', but got {context.loaded_message['payload'].name}"
