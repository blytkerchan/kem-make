# Session sub-layer for KEM-MAKE
Feature: Bounded tracking of unauthenticated handshake candidates
  As an implementer of KEM-MAKE
  I want candidate tracking bounded per-cid and globally, with fixed
  (non-sliding) expiry
  So that an attacker who forges structurally valid first-flight PDUs --
  which requires only public keys, not any private key -- cannot make a
  legitimate peer accumulate unbounded state, or keep a forged candidate
  alive indefinitely by replaying the message that created it

  Background:
    Given an empty candidate store

  Scenario: Adding a candidate makes it retrievable by its received bytes
    When I add a candidate for cid "cid-1" with received bytes "req-1" and sent bytes "resp-1"
    Then a candidate for cid "cid-1" matching received bytes "req-1" is found
    And its sent bytes are "resp-1"

  Scenario: A candidate for one cid does not match a lookup for a different cid
    Given a candidate for cid "cid-1" with received bytes "req-1" and sent bytes "resp-1"
    When I look up a candidate for cid "cid-2" matching received bytes "req-1"
    Then no candidate is found

  Scenario: Identical received bytes under different cids do not cross-match
    Given a candidate for cid "cid-1" with received bytes "shared-bytes" and sent bytes "resp-1"
    And a candidate for cid "cid-2" with received bytes "shared-bytes" and sent bytes "resp-2"
    When I look up a candidate for cid "cid-1" matching received bytes "shared-bytes"
    Then its sent bytes are "resp-1"
    When I look up a candidate for cid "cid-2" matching received bytes "shared-bytes"
    Then its sent bytes are "resp-2"

  Scenario: The per-cid candidate cap is enforced
    Given a candidate store with a per-cid cap of 2
    And 2 candidates already added for cid "cid-1"
    When I attempt to add a third candidate for cid "cid-1"
    Then adding the candidate fails with CandidateLimitExceeded
    And cid "cid-1" still has exactly 2 candidates

  Scenario: The per-cid candidate cap does not affect other cids
    Given a candidate store with a per-cid cap of 1
    And a candidate already added for cid "cid-1"
    When I attempt to add a second candidate for cid "cid-1"
    Then adding the candidate fails with CandidateLimitExceeded
    When I add a candidate for cid "cid-2"
    Then cid "cid-2" has exactly 1 candidate

  Scenario: The global candidate cap is enforced across cids
    Given a candidate store with a global cap of 3
    And 3 candidates already added, one each for 3 different cids
    When I attempt to add a candidate for a fourth, different cid
    Then adding the candidate fails with CandidateLimitExceeded

  Scenario: Promoting a candidate discards every sibling for its cid
    Given 2 candidates added for cid "cid-1"
    When I promote the first candidate for cid "cid-1"
    Then cid "cid-1" has no remaining candidates
    And neither of the original candidates for cid "cid-1" can be found by their received bytes

  Scenario: Discarding a cid removes all its candidates without promoting any
    Given 2 candidates added for cid "cid-1"
    When I discard cid "cid-1"
    Then cid "cid-1" has no remaining candidates

  Scenario: Expiry removes only candidates past their fixed TTL
    Given a candidate store with a TTL of 10 seconds
    And a candidate added for cid "cid-old" at time 0
    And a candidate added for cid "cid-new" at time 5
    When I sweep expired candidates at time 12
    Then cid "cid-old" has no remaining candidates
    And cid "cid-new" still has exactly 1 candidate

  Scenario: A matching lookup does not extend a candidate's expiry
    # Deliberate design decision, not an oversight: a run of legitimate
    # retries proves the request path works and the response path
    # doesn't, so extending the deadline wouldn't fix a broken return
    # path -- and letting a lookup slide the TTL would let an attacker
    # who captured one eliciting message keep a forged candidate alive
    # indefinitely just by replaying it.
    Given a candidate store with a TTL of 10 seconds
    And a candidate added for cid "cid-1" at time 0
    When I look up a candidate for cid "cid-1" matching its received bytes at time 5
    And I look up a candidate for cid "cid-1" matching its received bytes at time 9
    And I sweep expired candidates at time 10
    Then cid "cid-1" has no remaining candidates
