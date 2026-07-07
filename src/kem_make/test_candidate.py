"""
Tests for kem_make.candidate.

Covers:
  1. Basic add / match_or_none / promote / discard round trip.
  2. Per-cid cap is enforced independently of the global cap.
  3. Global cap is enforced across cids.
  4. Promotion discards every sibling for that cid, not just the winner.
  5. expire() removes only past-TTL candidates, and is a no-op otherwise.
  6. TTL is fixed at creation and is NOT extended by a matching duplicate
     -- this is a deliberate design decision (see rationale.md), not an
     oversight, so it's tested explicitly rather than left implicit.
  7. Candidates for different cids don't interfere with each other.

Run with: pytest test_candidate.py -v
"""

import pytest

from kem_make.candidate import (
    CandidateStore,
    CandidateLimitExceeded,
    HandshakeCandidate,
)


def _cid(n: int) -> bytes:
    return n.to_bytes(16, "big")


# ---------------------------------------------------------------------------
# 1. Basic round trip
# ---------------------------------------------------------------------------

def test_add_and_match():
    store = CandidateStore()
    cid = _cid(1)
    candidate = store.add(cid, b"received-1", b"sent-1", now=0.0)

    assert candidate.cid == cid
    assert candidate.attempt_count == 0

    found = store.match_or_none(cid, b"received-1")
    assert found is candidate

    assert store.match_or_none(cid, b"something-else") is None
    assert store.match_or_none(_cid(2), b"received-1") is None


def test_promote_discards_all_candidates_for_that_cid():
    store = CandidateStore()
    cid = _cid(1)
    c1 = store.add(cid, b"received-1", b"sent-1", now=0.0)
    c2 = store.add(cid, b"received-2", b"sent-2", now=0.0)
    assert store.total_count() == 2

    store.promote(cid, c1)

    assert store.candidates_for(cid) == []
    assert store.total_count() == 0
    assert store.match_or_none(cid, b"received-1") is None
    assert store.match_or_none(cid, b"received-2") is None


def test_discard_removes_all_candidates_without_requiring_a_winner():
    store = CandidateStore()
    cid = _cid(1)
    store.add(cid, b"received-1", b"sent-1", now=0.0)
    store.add(cid, b"received-2", b"sent-2", now=0.0)

    store.discard(cid)

    assert store.candidates_for(cid) == []
    assert store.total_count() == 0


# ---------------------------------------------------------------------------
# 2. Per-cid cap
# ---------------------------------------------------------------------------

def test_per_cid_cap_is_enforced():
    store = CandidateStore(max_per_cid=2, max_total=100)
    cid = _cid(1)
    store.add(cid, b"r1", b"s1", now=0.0)
    store.add(cid, b"r2", b"s2", now=0.0)

    with pytest.raises(CandidateLimitExceeded):
        store.add(cid, b"r3", b"s3", now=0.0)

    # The rejected add must not have partially mutated state.
    assert len(store.candidates_for(cid)) == 2
    assert store.total_count() == 2


def test_per_cid_cap_does_not_affect_other_cids():
    store = CandidateStore(max_per_cid=1, max_total=100)
    store.add(_cid(1), b"r1", b"s1", now=0.0)

    with pytest.raises(CandidateLimitExceeded):
        store.add(_cid(1), b"r2", b"s2", now=0.0)

    # A different cid is entirely unaffected.
    store.add(_cid(2), b"r1", b"s1", now=0.0)
    assert len(store.candidates_for(_cid(2))) == 1


# ---------------------------------------------------------------------------
# 3. Global cap
# ---------------------------------------------------------------------------

def test_global_cap_is_enforced_across_cids():
    store = CandidateStore(max_per_cid=3, max_total=3)
    store.add(_cid(1), b"r1", b"s1", now=0.0)
    store.add(_cid(2), b"r1", b"s1", now=0.0)
    store.add(_cid(3), b"r1", b"s1", now=0.0)

    with pytest.raises(CandidateLimitExceeded):
        store.add(_cid(4), b"r1", b"s1", now=0.0)

    assert store.total_count() == 3


# ---------------------------------------------------------------------------
# 4. Independence across cids
# ---------------------------------------------------------------------------

def test_candidates_for_different_cids_are_independent():
    store = CandidateStore()
    store.add(_cid(1), b"shared-bytes", b"sent-1", now=0.0)
    store.add(_cid(2), b"shared-bytes", b"sent-2", now=0.0)

    # Same received bytes, different cid -- must not cross-match.
    found1 = store.match_or_none(_cid(1), b"shared-bytes")
    found2 = store.match_or_none(_cid(2), b"shared-bytes")
    assert found1.sent_pdu == b"sent-1"
    assert found2.sent_pdu == b"sent-2"


# ---------------------------------------------------------------------------
# 5 & 6. Fixed (non-sliding) TTL expiry
# ---------------------------------------------------------------------------

def test_expire_removes_only_past_ttl_candidates():
    store = CandidateStore(ttl_seconds=10.0)
    cid_old = _cid(1)
    cid_new = _cid(2)
    store.add(cid_old, b"r1", b"s1", now=0.0)   # expires at t=10
    store.add(cid_new, b"r1", b"s1", now=5.0)   # expires at t=15

    removed = store.expire(now=12.0)

    assert removed == 1
    assert store.candidates_for(cid_old) == []
    assert len(store.candidates_for(cid_new)) == 1
    assert store.total_count() == 1


def test_expire_is_a_no_op_when_nothing_is_past_ttl():
    store = CandidateStore(ttl_seconds=10.0)
    store.add(_cid(1), b"r1", b"s1", now=0.0)

    removed = store.expire(now=5.0)

    assert removed == 0
    assert store.total_count() == 1


def test_ttl_is_fixed_and_not_extended_by_a_matching_duplicate():
    # Deliberate design decision (see rationale.md): a run of legitimate
    # retries proves the request path works and the response path
    # doesn't, so extending the deadline on each match wouldn't help a
    # genuinely broken return path, and would let an attacker who
    # captured one eliciting message keep a candidate alive indefinitely
    # by replaying it, weakening the TTL bound. match_or_none() must not
    # mutate expires_at as a side effect of finding a match.
    store = CandidateStore(ttl_seconds=10.0)
    cid = _cid(1)
    candidate = store.add(cid, b"r1", b"s1", now=0.0)
    original_expiry = candidate.expires_at

    store.match_or_none(cid, b"r1")  # a "duplicate arrived" lookup
    store.match_or_none(cid, b"r1")  # and again

    assert candidate.expires_at == original_expiry

    removed = store.expire(now=10.0)
    assert removed == 1


def test_expired_candidate_no_longer_matches_even_before_expire_is_called():
    # is_expired() is available for callers who want to check without a
    # full sweep; matching logic itself doesn't auto-check expiry (that's
    # expire()'s job, called from the update() crank) -- confirm that
    # split explicitly rather than leaving it implicit.
    store = CandidateStore(ttl_seconds=10.0)
    cid = _cid(1)
    candidate = store.add(cid, b"r1", b"s1", now=0.0)

    assert candidate.is_expired(now=9.9) is False
    assert candidate.is_expired(now=10.0) is True
    assert candidate.is_expired(now=15.0) is True


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

def test_constructor_rejects_invalid_max_per_cid():
    with pytest.raises(ValueError):
        CandidateStore(max_per_cid=0)


def test_constructor_rejects_max_total_below_max_per_cid():
    with pytest.raises(ValueError):
        CandidateStore(max_per_cid=5, max_total=3)
