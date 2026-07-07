"""
Bounded tracking of unauthenticated first-flight handshake candidates.

The threat this exists for: KEM encapsulation only needs a *public* key,
so anyone who has Alice's and Bob's public keys -- which are on the wire
in plaintext the moment a handshake starts -- can forge a structurally
valid SessionInitResponse (or SessionInitRequest) under a given cid,
without holding any private key at all. The forgery is only provably
wrong once someone actually derives and confirms the session key. Until
that confirmation, a peer holding a given cid may have more than one
candidate reply in flight for it: the real one, and zero or more forged
ones. Both this module and the party running it MUST treat every such
candidate as equally unauthenticated until one of them produces
cryptographic proof (a matching h_m, or a cM that decrypts
successfully).

This module owns exactly the bookkeeping needed to survive that ambiguity
without becoming a resource-exhaustion vector itself:
  - a small cap on how many candidates a single cid may accumulate,
  - a coarser cap on the total number of candidates tracked at once,
  - promotion (confirm one candidate, discard its siblings for that cid),
  - fixed-TTL expiry, swept on demand, with no per-candidate extension.
    TTL is fixed rather than sliding deliberately: if a peer is seeing
    retries of the same PDU, that means its own replies aren't reaching
    the other side, and no amount of holding a candidate open longer
    fixes a broken return path. Sliding would also weaken the DoS bound
    it's meant to enforce -- an attacker who captured one legitimate
    eliciting message could replay it indefinitely to keep a candidate
    (forged or otherwise) alive forever for free, since a matching
    duplicate costs nothing but a cache hit.

This module does not itself do any cryptography, parse any PDU, or decide
what "confirmed" means -- callers (SessionLayer, or whatever dispatcher
sits above it) hand it opaque received/sent byte strings and tell it when
a candidate has been proven correspondent. Keeping this module free of
protocol semantics is deliberate: the DoS-bounding logic here is the same
regardless of which specific message types are in play.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


DEFAULT_MAX_CANDIDATES_PER_CID = 3
DEFAULT_MAX_TOTAL_CANDIDATES = 1024
DEFAULT_CANDIDATE_TTL_SECONDS = 60.0


class CandidateStoreError(Exception):
    pass


class CandidateLimitExceeded(CandidateStoreError):
    """Raised when adding a candidate would exceed the per-cid or global
    cap. Callers should drop the eliciting message silently -- no
    wire-level error message is sent for anything in this threat class,
    since an attacker able to observe an error response learns their
    forgery attempt was noticed, for no benefit to the legitimate
    peer."""
    pass


@dataclass
class HandshakeCandidate:
    """One unauthenticated (received, sent) pair for a given cid.

    received_pdu / sent_pdu are opaque DER bytes as far as this module is
    concerned. Byte-exact equality is sufficient for duplicate detection
    specifically because DER is canonical: two semantically identical
    messages always produce identical bytes, so there is no need to parse
    and compare fields (see bottom.py's DER-canonicality enforcement,
    which is what makes this true).
    """
    cid: bytes
    received_pdu: bytes
    sent_pdu: bytes
    created_at: float
    expires_at: float
    attempt_count: int = 0

    def is_expired(self, now: float) -> bool:
        return now >= self.expires_at

    def matches_received(self, pdu: bytes) -> bool:
        return pdu == self.received_pdu


class CandidateStore:
    """Tracks HandshakeCandidate objects, bounded per-cid and globally,
    with fixed (non-sliding) TTL expiry.

    Not thread-safe. If a single process handles concurrent handshakes
    across threads, callers must serialize access to a shared instance
    themselves (a lock around each call is sufficient; nothing here holds
    a lock across calls or blocks).
    """

    def __init__(
        self,
        max_per_cid: int = DEFAULT_MAX_CANDIDATES_PER_CID,
        max_total: int = DEFAULT_MAX_TOTAL_CANDIDATES,
        ttl_seconds: float = DEFAULT_CANDIDATE_TTL_SECONDS,
    ):
        if max_per_cid < 1:
            raise ValueError("max_per_cid must be at least 1")
        if max_total < max_per_cid:
            raise ValueError("max_total must be at least max_per_cid")
        self._max_per_cid = max_per_cid
        self._max_total = max_total
        self._ttl_seconds = ttl_seconds
        self._by_cid: Dict[bytes, List[HandshakeCandidate]] = {}
        self._total = 0

    # -- queries -------------------------------------------------------

    def candidates_for(self, cid: bytes) -> List[HandshakeCandidate]:
        return list(self._by_cid.get(cid, []))

    def match_or_none(self, cid: bytes, received_pdu: bytes) -> Optional[HandshakeCandidate]:
        """Byte-exact match against an existing candidate for this cid.
        Callers use this BEFORE doing any protocol processing: a match
        means "resend the cached sent_pdu, do not re-run any handshake
        logic" -- this is what makes duplicate-PDU-in produces
        identical-PDU-out hold, rather than just usually holding."""
        for candidate in self._by_cid.get(cid, []):
            if candidate.matches_received(received_pdu):
                return candidate
        return None

    def total_count(self) -> int:
        return self._total

    # -- mutation --------------------------------------------------------

    def add(self, cid: bytes, received_pdu: bytes, sent_pdu: bytes, now: float) -> HandshakeCandidate:
        """Adds a new candidate. Raises CandidateLimitExceeded, without
        adding anything, if this would exceed either the per-cid or the
        global cap -- callers must treat that as "drop the message that
        would have created this candidate," not as a reason to retry the
        add or to tell the peer anything."""
        existing = self._by_cid.setdefault(cid, [])
        if len(existing) >= self._max_per_cid:
            raise CandidateLimitExceeded(
                f"cid already has {len(existing)} candidates (limit {self._max_per_cid})"
            )
        if self._total >= self._max_total:
            raise CandidateLimitExceeded(
                f"global candidate limit reached ({self._max_total})"
            )

        candidate = HandshakeCandidate(
            cid=cid,
            received_pdu=received_pdu,
            sent_pdu=sent_pdu,
            created_at=now,
            expires_at=now + self._ttl_seconds,
        )
        existing.append(candidate)
        self._total += 1
        return candidate

    def promote(self, cid: bytes, winner: HandshakeCandidate) -> None:
        """Called the instant a candidate produces cryptographic proof of
        correspondence. Discards every sibling candidate for that cid
        immediately, including `winner` itself -- once a session is
        promoted out of the candidate pool, its bookkeeping moves to the
        (now-confirmed) SessionLayer, not this store. Safe to call even
        if `winner` is not present (e.g. already expired and swept);
        the cid's remaining candidates are still discarded."""
        removed = self._by_cid.pop(cid, [])
        self._total -= len(removed)

    def discard(self, cid: bytes) -> None:
        """Discards every candidate for a cid without promoting any of
        them -- e.g. the handshake for this cid failed outright and no
        candidate should be retried or reconsidered."""
        removed = self._by_cid.pop(cid, [])
        self._total -= len(removed)

    def expire(self, now: float) -> int:
        """Sweeps every candidate across every cid and drops anything past
        its (fixed, never-extended) expiry. Returns the number removed.
        Intended to be called from update()'s crank on every tick -- see
        the module docstring for why TTL is fixed rather than refreshed
        on a matching retry."""
        removed_count = 0
        empty_cids = []
        for cid, candidates in self._by_cid.items():
            surviving = [c for c in candidates if not c.is_expired(now)]
            removed_count += len(candidates) - len(surviving)
            if surviving:
                self._by_cid[cid] = surviving
            else:
                empty_cids.append(cid)
        for cid in empty_cids:
            del self._by_cid[cid]
        self._total -= removed_count
        return removed_count
