from behave import given, when, then
from behave.api.pending_step import StepNotImplementedError

from kem_make.candidate import CandidateLimitExceeded, CandidateStore

@given(u'an empty candidate store')
def step_impl(context):
    context.candidate_store = CandidateStore()


@when(u'I add a candidate for cid "cid-1" with received bytes "req-1" and sent bytes "resp-1"')
def step_impl(context):
    context.candidate_store.add(
        cid=b"cid-1",
        received_pdu=b"req-1",
        sent_pdu=b"resp-1",
        now=0.0,
    )


@then(u'a candidate for cid "{cid}" matching received bytes "{received_bytes}" is found')
def step_impl(context, cid, received_bytes):
    candidate = context.candidate_store.match_or_none(
        cid=cid.encode("utf-8"),
        received_pdu=received_bytes.encode("utf-8"),
    )
    assert candidate is not None, f"Expected to find a candidate for cid '{cid}' matching received bytes '{received_bytes}', but none was found."
    context.candidate = candidate


@then(u'its sent bytes are "{sent_bytes}"')
def step_impl(context, sent_bytes):
    assert context.candidate.sent_pdu == sent_bytes.encode("utf-8"), f"Expected sent bytes to be '{sent_bytes}', but got {context.candidate.sent_pdu!r}"


@given(u'a candidate for cid "{cid}" with received bytes "{received_bytes}" and sent bytes "{sent_bytes}"')
def step_impl(context, cid, received_bytes, sent_bytes):
    context.candidate_store.add(
        cid=cid.encode("utf-8"),
        received_pdu=received_bytes.encode("utf-8"),
        sent_pdu=sent_bytes.encode("utf-8"),
        now=0.0,
    )


@when(u'I look up a candidate for cid "{cid}" matching received bytes "{received_bytes}"')
def step_impl(context, cid, received_bytes):
    context.candidate = context.candidate_store.match_or_none(
        cid=cid.encode("utf-8"),
        received_pdu=received_bytes.encode("utf-8"),
    )


@then(u'no candidate is found')
def step_impl(context):
    assert context.candidate is None, "Expected no candidate to be found, but one was found."


@given(u'a candidate store with a per-cid cap of {max_per_cid:d}')
def step_impl(context, max_per_cid):
    context.candidate_store = CandidateStore(max_per_cid=max_per_cid)


@given(u'2 candidates already added for cid "cid-1"')
def step_impl(context):
    for i in range(2):
        context.candidate_store.add(
            cid=b"cid-1",
            received_pdu=f"req-{i+1}".encode("utf-8"),
            sent_pdu=f"resp-{i+1}".encode("utf-8"),
            now=0.0,
        )


@when(u'I attempt to add a third candidate for cid "cid-1"')
def step_impl(context):
    try:
        context.candidate_store.add(
            cid=b"cid-1",
            received_pdu=b"req-3",
            sent_pdu=b"resp-3",
            now=0.0,
        )
    except CandidateLimitExceeded:
        context.candidate_limit_exceeded = True


@then(u'adding the candidate fails with CandidateLimitExceeded')
def step_impl(context):
    assert context.candidate_limit_exceeded, "Expected CandidateLimitExceeded, but it did not occur."


@then(u'cid "cid-1" still has exactly 2 candidates')
def step_impl(context):
    candidates = context.candidate_store.candidates_for(b"cid-1")
    assert len(candidates) == 2, f"Expected cid 'cid-1' to have exactly 2 candidates, but found {len(candidates)}"


@given(u'a candidate already added for cid "cid-1"')
def step_impl(context):
    context.candidate_store.add(
        cid=b"cid-1",
        received_pdu=b"req-1",
        sent_pdu=b"resp-1",
        now=0.0,
    )


@when(u'I attempt to add a second candidate for cid "cid-1"')
def step_impl(context):
    try:
        context.candidate_store.add(
            cid=b"cid-1",
            received_pdu=b"req-2",
            sent_pdu=b"resp-2",
            now=0.0,
        )
    except CandidateLimitExceeded:
        context.candidate_limit_exceeded = True

@when(u'I add a candidate for cid "{cid}"')
def step_impl(context, cid):
    context.candidate_store.add(
        cid=cid.encode("utf-8"),
        received_pdu=b"req-1",
        sent_pdu=b"resp-1",
        now=0.0,
    )


@then(u'cid "{cid}" has exactly {candidate_count:d} candidate')
def step_impl(context, cid, candidate_count):
    candidates = context.candidate_store.candidates_for(cid.encode("utf-8"))
    assert len(candidates) == candidate_count, f"Expected cid '{cid}' to have exactly {candidate_count} candidate(s), but found {len(candidates)}"


@given(u'a candidate store with a global cap of {max_total:d}')
def step_impl(context, max_total):
    context.candidate_store = CandidateStore(max_total=max_total)


@given(u'{candidate_count:d} candidates already added, one each for {cid_count:d} different cids')
def step_impl(context, candidate_count, cid_count):
    assert candidate_count == cid_count, "This step assumes one candidate per cid"
    for i in range(candidate_count):
        context.candidate_store.add(
            cid=f"cid-{i+1}".encode("utf-8"),
            received_pdu=f"req-{i+1}".encode("utf-8"),
            sent_pdu=f"resp-{i+1}".encode("utf-8"),
            now=0.0,
        )


@when(u'I attempt to add a candidate for a fourth, different cid')
def step_impl(context):
    try:
        context.candidate_store.add(
            cid=b"cid-4",
            received_pdu=b"req-4",
            sent_pdu=b"resp-4",
            now=0.0,
        )
    except CandidateLimitExceeded:
        context.candidate_limit_exceeded = True


@given(u'{candidate_count:d} candidates added for cid "{cid}"')
def step_impl(context, candidate_count, cid):
    for i in range(candidate_count):
        context.candidate_store.add(
            cid=cid.encode("utf-8"),
            received_pdu=f"req-{i+1}".encode("utf-8"),
            sent_pdu=f"resp-{i+1}".encode("utf-8"),
            now=0.0,
        )


@when(u'I promote the first candidate for cid "{cid}"')
def step_impl(context, cid):
    context.candidate_store.promote(cid.encode("utf-8"), context.candidate_store.candidates_for(cid.encode("utf-8"))[0])


@then(u'cid "{cid}" has no remaining candidates')
def step_impl(context, cid):
    candidates = context.candidate_store.candidates_for(cid.encode("utf-8"))
    assert len(candidates) == 0, f"Expected cid '{cid}' to have no remaining candidates, but found {len(candidates)}"


@then(u'neither of the original candidates for cid "{cid}" can be found by their received bytes')
def step_impl(context, cid):
    for i in range(2):
        candidate = context.candidate_store.match_or_none(
            cid=cid.encode("utf-8"),
            received_pdu=f"req-{i+2}".encode("utf-8"), # note the +2: the original initial candidate was promoted in this scenario
        )
        assert candidate is None, f"Expected no candidate to be found for cid '{cid}' with received bytes 'req-{i+1}', but one was found."


@when(u'I discard cid "{cid}"')
def step_impl(context, cid):
    context.candidate_store.discard(cid.encode("utf-8"))


@given(u'a candidate store with a TTL of {ttl} seconds')
def step_impl(context, ttl):
    context.candidate_store = CandidateStore(ttl_seconds=float(ttl))


@given(u'a candidate added for cid "{cid}" at time {now:f}')
def step_impl(context, cid, now):
    context.candidate_store.add(
        cid=cid.encode("utf-8"),
        received_pdu=b"req",
        sent_pdu=b"resp",
        now=now,
    )


@when(u'I sweep expired candidates at time {now:f}')
def step_impl(context, now):
    context.candidate_store.expire(now=now)


@then(u'cid "cid-new" still has exactly 1 candidate')
def step_impl(context):
    candidates = context.candidate_store.candidates_for(b"cid-new")
    assert len(candidates) == 1, f"Expected cid 'cid-new' to have exactly 1 candidate, but found {len(candidates)}"


@when(u'I look up a candidate for cid "{cid}" matching its received bytes at time {now:f}')
def step_impl(context, cid, now):
    context.candidate_store.match_or_none(
        cid=cid.encode("utf-8"),
        received_pdu=b"req",
    )


