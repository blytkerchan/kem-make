"""
Dispatcher: multi-candidate arbitration for the Mallory scenario.

The threat this exists for (see rationale.md and session.py's own
docstring for the full background): forging a SessionInitResponse
requires no private key at all, only Alice's and Bob's already-public
keys. So after Alice sends ONE SessionInitRequest under some cid, she
may legitimately receive MORE THAN ONE candidate SessionInitResponse
under that same cid -- the real Bob's, plus zero or more forged ones
from anyone who observed the request. She has no way to tell them apart
until one of them produces cryptographic proof (a matching h_m).

This is asymmetric, and deliberately not handled symmetrically here.
Verified directly (not just argued) before building this: a forged
SessionInitRequest claiming to be Alice can never actually complete a
handshake, because doing so requires decapsulating ct1 -- which was
encapsulated by the real Alice against the real Bob's static public key,
using ONLY Bob's real static private key. A forger has no way to obtain
that, regardless of which side of the exchange they're impersonating.
So the responder side needs only the bounded-candidate-count and
fixed-TTL protection CandidateStore already provides for a single
Session per cid -- it does not need multiple competing Session
instances the way the initiator side does. This module reflects that
asymmetry: responder-side cid handling is a single Session, gated
by CandidateStore's caps; initiator-side cid handling may fork into
several concurrent Session candidates, arbitrated here.

How forking works
------------------
Session.fork() (see session.py) creates a sibling instance sharing
the pre-response handshake state (cid, ephemeral keypair, s1, peer
identity) but with independent output queues, ready to process a
DIFFERENT SessionInitResponse from scratch. Dispatcher keeps one
untouched "template" fork per pending initiator cid specifically to
spawn further candidates from, and a list of "live" forks actually
processing distinct candidate responses.

CandidateStore is reused for both roles' first real response-generating
step, not just the responder side: for the responder, it tracks
(SessionInitRequest received, SessionInitResponse sent); for the
initiator, it tracks (SessionInitResponse received, SessionCompletionRequest
sent) per fork. Same caps, same TTL, same store -- the "bound how much
unauthenticated state one cid or the whole system can accumulate" need is
identical in shape regardless of which PDU pair it's protecting.

Promotion is immediate and total: the instant any fork (or the single
responder session) reaches ESTABLISHED, every sibling for that cid is
discarded right there -- not on the next update() tick, and not
contingent on the losing candidates ever producing a reply (a forged
candidate may simply never get a matching response and would otherwise
just sit there until its own TTL; there is no reason to wait for that
once a winner already exists).

No wire-level error message is ever produced for a losing candidate,
consistent with session.py and candidate.py: discarding is silent.

Not thread-safe, matching CandidateStore's own stated contract -- if a
single process handles concurrent handshakes across threads, callers
must serialize access to a shared Dispatcher instance themselves.
"""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional, Tuple

from .bottom import MakeMessage
from .candidate import CandidateStore, CandidateLimitExceeded
from .session import (
    Session,
    Role,
    SessionState,
    UpdateResult,
    SessionConfig,
    HandshakeFailed,
    UnexpectedPDU,
    KeyLookup,
    KeyId,
    next_update_result,
)


class DispatcherError(Exception):
    """Raised for any error in the Dispatcher itself."""


class Dispatcher:
    """
    Multi-candidate arbitration for the Mallory scenario."""
    #pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        key_lookup: KeyLookup,
        config: Optional[SessionConfig] = None,
        candidate_store: Optional[CandidateStore] = None,
    ):
        self._keys = key_lookup
        self.config = config or SessionConfig()
        self._candidates = candidate_store or CandidateStore()

        # Confirmed sessions, either role, one per cid.
        self._established: Dict[uuid.UUID, Session] = {}
        # Responder side: at most one Session per pending cid --
        # see module docstring for why no arbitration is needed here.
        self._responder_sessions: Dict[uuid.UUID, Session] = {}
        # Initiator side: an untouched template to fork() from, plus the
        # list of live forks actually processing distinct candidates.
        self._initiator_templates: Dict[uuid.UUID, Session] = {}
        self._initiator_forks: Dict[uuid.UUID, List[Session]] = {}

        self._outgoing_pdus: List[bytes] = []
        self._outgoing_payloads: List[Tuple[uuid.UUID, bytes]] = []

    # -- initiating a handshake ---------------------------------------------

    def initiate(self, own_key_id: KeyId, peer_key_id: KeyId, now: float) -> uuid.UUID:
        """Starts a new handshake as an initiator, returning the cid to
        use for all subsequent PDUs in this handshake. The returned cid
        is unique to this handshake."""
        primary = Session(Role.INITIATOR, own_key_id, self._keys, self.config)
        primary.initiate(peer_key_id, now)
        cid = primary.cid

        # primary itself serves as the permanent template -- fork() never
        # mutates self, so it's safe to call repeatedly on the same
        # object for every incoming response, including the first.
        # primary is deliberately NOT added to _initiator_forks: it never
        # itself processes a response, only spawns forks that do.
        self._initiator_templates[cid] = primary
        self._initiator_forks[cid] = []
        while primary.poll_pdu():
            self._outgoing_pdus.append(primary.get_pdu())
        return cid

    # -- push in --------------------------------------------------------

    def post_pdu(self, der_bytes: bytes, now: float) -> None:
        """Processes an incoming PDU, routing it to the appropriate session layer based on its
        correlation ID."""
        der_bytes = bytes(der_bytes)
        try:
            msg = MakeMessage.load(der_bytes)
        except ValueError:
            # Malformed input silently dropped, matching session.py.
            # ValueError, not just NonCanonicalEncoding/InvalidCorrelationId:
            # those two are for input that DOES parse but fails a specific
            # named check; input that doesn't even parse as a MakeMessage
            # SEQUENCE raises a plain ValueError straight out of asn1crypto,
            # and must be dropped the same way.
            return
        cid = msg.correlation_id
        payload_name = msg["payload"].name

        if cid in self._established:
            self._deliver(self._established[cid], der_bytes, now, cid)
            return

        if payload_name == "session_init_request":
            self._route_session_init_request(cid, der_bytes, now)
            return

        if payload_name == "session_init_response":
            self._route_session_init_response(cid, der_bytes, now)
            return

        # session_completion_request only ever makes sense for a
        # responder session; session_completion_response and message can
        # apply to either an in-flight responder session or one of
        # several in-flight initiator forks.
        if cid in self._responder_sessions:
            self._deliver(self._responder_sessions[cid], der_bytes, now, cid)
            self._reap_responder(cid)
            return

        if cid in self._initiator_forks:
            self._route_to_forks(cid, der_bytes, now)
            return
        # Unknown cid for a PDU type that isn't a first-flight message --
        # nothing to route to. Silently dropped.

    def post_payload(self, cid: uuid.UUID, payload: bytes) -> None:
        """Posts an application payload to the established session for the given cid.
        Raises DispatcherError if no such session exists."""
        if cid in self._established:
            self._established[cid].post_payload(payload)
            return
        if cid in self._responder_sessions:
            self._responder_sessions[cid].post_payload(payload)
            return
        if cid in self._initiator_templates:
            # Queue on the template so every FUTURE fork inherits it (see
            # fork()'s own docstring), and on every currently-live fork so
            # candidates that already exist get it too, not just ones
            # spawned after this call.
            self._initiator_templates[cid].post_payload(payload)
            for fork in self._initiator_forks.get(cid, []):
                fork.post_payload(payload)
            return
        raise DispatcherError(f"no established or in-flight session for cid {cid}")

    # -- pull out ---------------------------------------------------------

    def poll_pdu(self) -> bool:
        """Returns True if there are any outgoing PDUs queued, False otherwise."""
        return len(self._outgoing_pdus) > 0

    def get_pdu(self) -> bytes:
        """Returns the next outgoing PDU, removing it from the queue.
        Raises IndexError if none are queued."""
        return self._outgoing_pdus.pop(0)

    def poll_payload(self) -> bool:
        """Returns True if there are any outgoing application payloads queued, False otherwise."""
        return len(self._outgoing_payloads) > 0

    def get_payload(self) -> Tuple[uuid.UUID, bytes]:
        """Returns the next outgoing application payload, removing it from the queue.
        Raises IndexError if none are queued."""
        return self._outgoing_payloads.pop(0)

    def close(self, cid: uuid.UUID) -> None:
        """Explicitly ends an established session and forgets it.

        Without this, _established only ever grows for the life of a
        Dispatcher instance -- there is deliberately no idle-timeout or
        max-lifetime policy for established sessions here (see
        rationale.md: that's a decision for whatever sits above this,
        which knows what "the session is done" actually means for the
        application). This is the minimum viable way for a caller who
        DOES know a session is over to say so, without which there would
        be no way to release one at all short of dropping the whole
        Dispatcher. Not sending anything on the wire -- this is a purely
        local bookkeeping operation, consistent with no-wire-level-error
        policy elsewhere in this module.
        """
        self._established.pop(cid, None)

    # -- the crank ---------------------------------------------------------

    def update(self, now: float) -> Tuple[UpdateResult, float]:
        """Cranks every live session and fork, reaps anything DROPPED,
        and promotes the first fork (or responder session) that reaches
        ESTABLISHED for its cid, discarding all siblings immediately.

        Returns (result, next_deadline) mirroring Session.update()'s
        own contract: result reflects whether anything is ready to poll
        across every session/fork this crank touched, and next_deadline
        is the earliest of every individual session/fork's own next
        deadline -- callers drive this the same way they'd drive a bare
        Session, just at the multi-session level.
        """
        self._candidates.expire(now)
        self._reconcile_expired_candidates()

        next_deadline = float("inf")

        next_deadline = self._update_established_sessions(now, next_deadline)
        next_deadline = self._update_responder_sessions(now, next_deadline)

        next_deadline = self._process_initiator_forks(now, next_deadline)

        if next_deadline == float("inf"):
            next_deadline = now + self.config.retry_interval_seconds
        return next_update_result(self, next_deadline)

    def _process_initiator_forks(self, now: float, next_deadline: float) -> float:
        for cid in list(self._initiator_forks):
            winner = None
            surviving: list[Session] = []
            for fork in self._initiator_forks[cid]:
                try:
                    _, deadline = fork.update(now)
                    next_deadline = min(next_deadline, deadline)
                except (HandshakeFailed, UnexpectedPDU):
                    continue  # this candidate lost; just don't keep it
                if fork.state is SessionState.ESTABLISHED:
                    winner = fork
                    break
                if fork.state is not SessionState.DROPPED:
                    surviving.append(fork)
            if winner is not None:
                self._drain(winner, cid)
                self._promote(cid, winner)
            elif surviving:
                self._initiator_forks[cid] = surviving
            else:
                del self._initiator_forks[cid]
                self._initiator_templates.pop(cid, None)
                self._candidates.discard(cid)
        return next_deadline

    def _update_responder_sessions(self, now: float, next_deadline: float) -> float:
        for cid in list(self._responder_sessions):
            session = self._responder_sessions[cid]
            try:
                _, deadline = session.update(now)
            except (HandshakeFailed, UnexpectedPDU):
                del self._responder_sessions[cid]
                self._candidates.discard(cid)
                continue
            next_deadline = min(next_deadline, deadline)
            self._drain(session, cid)
            if session.state is SessionState.ESTABLISHED:
                self._promote(cid, session)
            elif session.state is SessionState.DROPPED:
                del self._responder_sessions[cid]
                self._candidates.discard(cid)
        return next_deadline

    def _update_established_sessions(self, now: float, next_deadline: float) -> float:
        for cid, session in list(self._established.items()):
            try:
                _, deadline = session.update(now)
                next_deadline = min(next_deadline, deadline)
            except (HandshakeFailed, UnexpectedPDU):
                pass
            self._drain(session, cid)
        return next_deadline

    # -- internal: routing ---------------------------------------------------

    def _route_session_init_request(self, cid: uuid.UUID, der_bytes: bytes, now: float) -> None:
        if cid in self._responder_sessions:
            self._deliver(self._responder_sessions[cid], der_bytes, now, cid)
            self._reap_responder(cid)
            return

        try:
            self._candidates.add(cid, der_bytes, sent_pdu=b"", now=now)
        except CandidateLimitExceeded:
            return  # dropped silently, per policy

        session = Session(Role.RESPONDER, None, self._keys, self.config)
        # Responder role doesn't need its own_key_id until it resolves
        # key_id_b from the request itself -- see session.py.
        self._responder_sessions[cid] = session
        self._deliver(session, der_bytes, now, cid)
        if session.state is SessionState.INITIAL:
            # _handle_session_init_request raised HandshakeFailed before
            # ever reaching its own state transition (unknown claimed
            # identity, no mutual AEAD, etc.) -- this session can never
            # become anything but permanently invalid, so there's no
            # reason to let it linger in _responder_sessions until its
            # TTL expires; clean it up immediately instead.
            del self._responder_sessions[cid]
            self._candidates.discard(cid)
            return
        # Now that a real response exists, record it against this cid so
        # the candidate entry reflects the actual (request, response)
        # pair, not a placeholder.
        if session.state is SessionState.EXPECT_SESSION_COMPLETION_REQUEST:
            entries = self._candidates.candidates_for(cid)
            if entries:
                entries[0].sent_pdu = session.get_last_sent() or b""
        self._reap_responder(cid)

    def _route_session_init_response(self, cid: uuid.UUID, der_bytes: bytes, now: float) -> None:
        if cid not in self._initiator_templates:
            return  # not a cid we initiated; nothing to fork from

        for fork in self._initiator_forks.get(cid, []):
            if fork.get_last_received() == der_bytes:
                self._deliver(fork, der_bytes, now, cid)
                return  # exact duplicate of an already-tried candidate

        try:
            self._candidates.add(cid, der_bytes, sent_pdu=b"", now=now)
        except CandidateLimitExceeded:
            return  # dropped silently: too many candidates for this cid

        new_fork = self._initiator_templates[cid].fork()
        self._initiator_forks.setdefault(cid, []).append(new_fork)
        self._deliver(new_fork, der_bytes, now, cid)
        entries = self._candidates.candidates_for(cid)
        for entry in entries:
            if entry.received_pdu == der_bytes:
                entry.sent_pdu = new_fork.get_last_sent() or b""

    def _route_to_forks(self, cid: uuid.UUID, der_bytes: bytes, now: float) -> None:
        for fork in list(self._initiator_forks.get(cid, [])):
            try:
                fork.post_pdu(der_bytes)
                fork.update(now)
            except (HandshakeFailed, UnexpectedPDU):
                continue
            if fork.state is SessionState.ESTABLISHED:
                self._drain(fork, cid)
                self._promote(cid, fork)
                return

    # -- internal: bookkeeping -----------------------------------------------

    def _deliver(self, session: Session, der_bytes: bytes, now: float, cid: uuid.UUID) -> None:
        session.post_pdu(der_bytes)
        try:
            session.update(now)
        except (HandshakeFailed, UnexpectedPDU):
            pass
        self._drain(session, cid)

    def _drain(self, session: Session, cid: uuid.UUID) -> None:
        while session.poll_pdu():
            self._outgoing_pdus.append(session.get_pdu())
        while session.poll_payload():
            self._outgoing_payloads.append((cid, session.get_payload()))

    def _promote(self, cid: uuid.UUID, winner: Session) -> None:
        self._established[cid] = winner
        self._responder_sessions.pop(cid, None)
        self._initiator_forks.pop(cid, None)
        self._initiator_templates.pop(cid, None)
        self._candidates.discard(cid)

    def _reap_responder(self, cid: uuid.UUID) -> None:
        session = self._responder_sessions.get(cid)
        if session is None:
            return
        if session.state is SessionState.ESTABLISHED:
            self._drain(session, cid)
            self._promote(cid, session)
        elif session.state is SessionState.DROPPED:
            del self._responder_sessions[cid]
            self._candidates.discard(cid)

    def _reconcile_expired_candidates(self) -> None:
        for cid in list(self._responder_sessions):
            if not self._candidates.candidates_for(cid):
                del self._responder_sessions[cid]
        for cid in list(self._initiator_forks):
            if not self._candidates.candidates_for(cid) and cid not in self._established:
                self._initiator_forks.pop(cid, None)
                self._initiator_templates.pop(cid, None)
