import uuid

from behave import when, then, given
from behave.api.pending_step import StepNotImplementedError

from kem_make import bottom

@given(u'application payload bytes "m_data"')
def step_impl(context):
    context.m_data = b"m_data"


@when(u'I build a Message with seq=1 and m="m_data"')
def step_impl(context):
    msg = bottom.Message({"seq": 1, "m": context.m_data})
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": bottom.MakePayload("message", msg)})


@then(u'the Message round-trips through DER encoding unchanged')
def step_impl(context):
    der = context.message.dump()
    context.loaded_message = bottom.MakeMessage.load(der)
    assert context.loaded_message.dump() == context.message.dump(), "Loaded message does not match the original message after DER round-trip" 


@then(u'its "seq" field equals 1')
def step_impl(context):
    assert context.loaded_message["payload"].chosen["seq"].native == 1, "Loaded message's seq field does not equal 1"


@then(u'its "m" field equals "m_data"')
def step_impl(context):
    assert context.loaded_message["payload"].chosen["m"].native == context.m_data, "Loaded message's m field does not equal the expected data"


@when(u'I attempt to build a Message with only m="m_data" and no "seq"')
def step_impl(context):
    try:
        msg = bottom.Message({"m": context.m_data})
        context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": bottom.MakePayload("message", msg)})
    except ValueError as e:
        context.build_exception = e
        context.error_raised = True
    else:
        context.error_raised = False

@then(u'encoding the Message fails')
def step_impl(context):
    assert context.error_raised, "Expected an error to be raised when building the Message, but no error was raised"


@when(u'I attempt to build a Message with only seq=1 and no "m"')
def step_impl(context):
    try:
        msg = bottom.Message({"seq": 1})
        context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": bottom.MakePayload("message", msg)})
    except ValueError as e:
        context.build_exception = e
        context.error_raised = True
    else:
        context.error_raised = False


@given(u'a built Message with seq=1 and m="m_data"')
def step_impl(context):
    msg = bottom.Message({"seq": 1, "m": context.m_data})
    context.message = bottom.MakeMessage({"cid": uuid.uuid4().bytes, "payload": bottom.MakePayload("message", msg)})


@then(u'the Message has exactly the fields "seq" and "m"')
def step_impl(context):
    assert context.message["payload"].chosen.native.keys() == {"seq", "m"}, "Message does not have exactly the fields 'seq' and 'm'"

