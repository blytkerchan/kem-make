"""
KEM-MAKE session layer.

Implements the mutually-authenticated key exchange with perfect forward
secrecy described in main.pdf ("Performing a mutually authenticated key
exchange with perfect forward secrecy using a KEM"), on top of the wire
structures in bottom.py, as a transport-agnostic state machine.

Interface shape
----------------
Deliberately modeled on push-in/pull-out/crank, not callbacks:

    post_pdu(bytes)        transport  -> layer   (raw MakeMessage DER)
    post_payload(bytes)    application -> layer  (plaintext to send)
    poll_pdu() / get_pdu()             layer -> transport
    poll_payload() / get_payload()     layer -> application
    update(now)                        does all the actual work

update() is where every state transition, every crypto operation, every
retry decision, and all TTL expiry happens. post_*() only enqueues;
nothing it does is observable via poll_*()/get_*() until the next
update() call. This split is deliberate: a callback firing synchronously
from inside post_pdu() would put the layer's own internals on the call
stack at a point where the caller might reenter it, and a pure state
machine with no callbacks is far easier to drive from a test than one
that expects a handler object to be watching.

This class represents ONE handshake attempt for ONE cid -- either the
initiator's (Alice's) side or the responder's (Bob's) side of it, chosen
at construction via `role`. It does NOT implement multi-candidate
arbitration (the DoS-mitigation concern: an unauthenticated first-flight
PDU for a given cid may have more than one plausible responder in
flight, since forging one requires only public keys). That arbitration
is the job of an outer dispatcher that uses candidate.py's
CandidateStore to bound how many concurrent Session instances may
exist for one cid before any of them is cryptographically confirmed, and
promotes exactly one (discarding its siblings) the moment proof arrives.
This class is the thing that gets constructed once per candidate, and
once per confirmed session thereafter.

Retry semantics
----------------
Retries resend the EXACT bytes already sent for the current state, never
regenerated ones. This is a correctness requirement, not a style
preference: regenerating ephemeral keys on retry would produce a
structurally valid but cryptographically different message, silently
diverging from whatever the peer already derived from the original.
Both `_last_received` and `_last_sent` are single slots, overwritten on
every successful state transition, not a history: they represent "the
pair relevant to the step currently being waited on," per an explicit
design decision, not an oversight.

Threat-model notes that directly shape what this class does on failure:
  - KEM encapsulation needs only a public key, so a peer's identity is
    NOT authenticated until h_m matches (initiator side) or c_m/`m`
    successfully decrypts (responder side, one step earlier). Every
    field this class reads from the wire before that point must be
    treated as attacker-controlled.
  - No wire-level error message exists anywhere in this protocol as
    currently specified. Every failure path in this module either
    raises a local (Python-only) exception for the caller to act on, or
    -- for the specific case of retry/TTL exhaustion -- simply produces
    no further output. Nothing here ever causes a message to be sent
    telling a peer (legitimate or attacking) that something went wrong.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple, runtime_checkable

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import mlkem

from .bottom import (
    MakeMessage,
    SessionInitRequest,
    SessionInitResponse,
    SessionCompletionRequest,
    SessionCompletionResponse,
    Message,
    KemPublicKey,
    KemCiphertext,
    KeyId,
    AeadAlgorithmList,
    AEAD_OIDS,
    aead_name,
    MLKEM_OIDS,
    UnknownKemAlgorithm,
)


# ---------------------------------------------------------------------------
# ML-KEM plumbing (level 512 excluded throughout this project -- see
# crypto_backend.py's own notes on why; 768/1024 only)
# ---------------------------------------------------------------------------

_MLKEM_PUBLIC_CLASSES = {768: mlkem.MLKEM768PublicKey, 1024: mlkem.MLKEM1024PublicKey}
_MLKEM_PRIVATE_CLASSES = {768: mlkem.MLKEM768PrivateKey, 1024: mlkem.MLKEM1024PrivateKey}
_OID_TO_LEVEL = {oid: level for level, oid in MLKEM_OIDS.items() if level in _MLKEM_PRIVATE_CLASSES}

_AEAD_KEY_LENGTHS = {"aes256-gcm": 32, "chacha20-poly1305": 32}
_AEAD_NONCE_LENGTH = 12  # both AES-GCM and ChaCha20-Poly1305 use 12-byte nonces


def _level_of(kem_public_key: KemPublicKey) -> int:
    oid = kem_public_key["algorithm"]["algorithm"].dotted
    try:
        return _OID_TO_LEVEL[oid]
    except KeyError as e:
        raise UnknownKemAlgorithm(f"unsupported ML-KEM OID for the session layer: {oid}") from e


def _generate_ephemeral(level: int):
    private = _MLKEM_PRIVATE_CLASSES[level].generate()
    public_wire = KemPublicKey.build(private.public_key().public_bytes_raw(), level=level)
    return private, public_wire


def _encapsulate(peer_public: KemPublicKey):
    level = _level_of(peer_public)
    public_obj = _MLKEM_PUBLIC_CLASSES[level].from_public_bytes(peer_public["public_key"].native)
    shared_secret, ct_bytes = public_obj.encapsulate()
    return shared_secret, KemCiphertext.build(ct_bytes, level=level)


def _decapsulate(private_seed: bytes, level: int, ciphertext: KemCiphertext) -> bytes:
    private_obj = _MLKEM_PRIVATE_CLASSES[level].from_seed_bytes(bytes(private_seed))
    return private_obj.decapsulate(ciphertext["ciphertext"].native)


# ---------------------------------------------------------------------------
# Session key derivation
#
# k <- H(nA|nB, fA, s1|s2|s3|s4) per main.pdf, extended (per bottom.py's own
# existing Message-layer commentary) into two INDEPENDENT directional
# keys+IVs rather than one shared key: same HKDF salt/IKM, distinct info
# labels per direction. Per-message nonces are IV-XOR-seq (the same
# construction TLS 1.3 uses for its per-record nonce) rather than
# randomly generated per message -- random nonces would need their own
# uniqueness bookkeeping this project already does better with seq,
# which every Message already carries.
# ---------------------------------------------------------------------------

@dataclass
class SessionKeys:
    """The four secrets derived from the handshake, plus the AEAD name"""
    aead_name: str
    key_a2b: bytes
    iv_a2b: bytes
    key_b2a: bytes
    iv_b2a: bytes


def derive_session_keys( #pylint: disable=too-many-arguments,too-many-positional-arguments
    n_a: bytes, n_b: bytes, f_a: bytes, s1: bytes, s2: bytes, s3: bytes, s4: bytes, aead: str,
) -> SessionKeys:
    """Derive the four directional secrets from the handshake's shared secrets and nonces, plus
    the AEAD name. Raises ValueError if the AEAD is unsupported."""
    if aead not in _AEAD_KEY_LENGTHS:
        raise ValueError(f"unsupported AEAD for session key derivation: {aead}")
    key_length = _AEAD_KEY_LENGTHS[aead]
    salt = n_a + n_b
    ikm = s1 + s2 + s3 + s4

    def derive(label: bytes, length: int) -> bytes:
        hkdf = HKDF(algorithm=_hashes.SHA256(), length=length, salt=salt, info=f_a + label)
        return hkdf.derive(ikm)

    return SessionKeys(
        aead_name=aead,
        key_a2b=derive(b"kem-make-session-a2b-key-v1", key_length),
        iv_a2b=derive(b"kem-make-session-a2b-iv-v1", _AEAD_NONCE_LENGTH),
        key_b2a=derive(b"kem-make-session-b2a-key-v1", key_length),
        iv_b2a=derive(b"kem-make-session-b2a-iv-v1", _AEAD_NONCE_LENGTH),
    )


def _nonce_for_seq(iv: bytes, seq: int) -> bytes:
    seq_bytes = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq_bytes))


def _aead_cipher(aead: str, key: bytes):
    if aead == "aes256-gcm":
        return AESGCM(key)
    if aead == "chacha20-poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"unsupported AEAD: {aead}")


def _encrypt( #pylint: disable=too-many-arguments,too-many-positional-arguments
    aead: str,
    key: bytes,
    iv: bytes,
    seq: int,
    plaintext: bytes,
    associated_data: bytes,
    ) -> bytes:
    cipher = _aead_cipher(aead, key)
    nonce = _nonce_for_seq(iv, seq)
    return cipher.encrypt(nonce, plaintext, associated_data)


def _decrypt( #pylint: disable=too-many-arguments,too-many-positional-arguments
    aead: str,
    key: bytes,
    iv: bytes,
    seq: int,
    ciphertext: bytes,
    associated_data: bytes,
    ) -> bytes:
    cipher = _aead_cipher(aead, key)
    nonce = _nonce_for_seq(iv, seq)
    return cipher.decrypt(nonce, ciphertext, associated_data)  # raises InvalidTag on failure


# ---------------------------------------------------------------------------
# Public enums / exceptions / protocols
# ---------------------------------------------------------------------------

class Role(enum.Enum):
    """The two roles a Session may play in a handshake."""
    INITIATOR = "initiator"   # Alice
    RESPONDER = "responder"   # Bob


class SessionState(enum.Enum):
    """The states a Session may be in. The state machine is linear, with transitions following
    the handshake protocol."""
    INITIAL = "initial"
    EXPECT_SESSION_INIT_RESPONSE = "expect_session_init_response"           # initiator only
    EXPECT_SESSION_COMPLETION_REQUEST = "expect_session_completion_request"  # responder only
    EXPECT_SESSION_COMPLETION_RESPONSE = "expect_session_completion_response"  # initiator only
    ESTABLISHED = "established"
    DROPPED = "dropped"


class UpdateResult(enum.Enum):
    """The possible results of calling update() on a Session."""
    NOTHING_READY = "nothing_ready"
    PDU_READY = "pdu_ready"
    PAYLOAD_READY = "payload_ready"
    SESSION_DROPPED = "session_dropped"


class SessionError(Exception):
    """Base class for all exceptions this module raises."""


class UnexpectedPDU(SessionError):
    """A structurally valid MakeMessage arrived, but not one legal for the
    current (role, state)."""


class HandshakeFailed(SessionError):
    """Raised when something that must be cryptographically true wasn't:
    an unknown claimed identity, no mutually acceptable AEAD, a
    decryption/h_m mismatch. Never causes any PDU to be sent -- see
    module docstring on wire-level errors."""


class RetriesExhausted(SessionError):
    """Raised by update() when the configured retry budget is spent
    without a reply. The session moves to DROPPED; no PDU is sent."""


@runtime_checkable
class KeyLookup(Protocol):
    """Structural interface this module needs from a key store. The real
    KeyDirectory (keystore.py) already satisfies this; tests can supply a
    lightweight fake instead of standing up a whole KeyDirectory."""
    def get_public_key(self, key_id: KeyId) -> KemPublicKey: ... #pylint: disable=missing-function-docstring
    def get_private_key(self, key_id: KeyId): ...  # bytes or bytearray  #pylint: disable=missing-function-docstring


@dataclass
class SessionConfig:
    """Configurable parameters for a Session instance."""
    max_retries: int = 2                     # 2 retries => 3 total attempts
    retry_interval_seconds: float = 5.0
    ttl_seconds: float = 60.0                  # generous margin over the retry
                                                # span, since peers don't
                                                # coordinate timeout settings
    kem_level: int = 768
    acceptable_aeads: Tuple[str, ...] = ("aes256-gcm", "chacha20-poly1305")


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    """Manages the state and cryptographic context of a session between two parties."""
    #pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        role: Role,
        own_key_id: Optional[KeyId],
        key_lookup: KeyLookup,
        config: Optional[SessionConfig] = None,
    ):
        # own_key_id may be None ONLY for a RESPONDER: the responder
        # doesn't know which of its own keys it's being addressed as
        # until it resolves key_id_b out of the incoming
        # SessionInitRequest itself (see _handle_session_init_request).
        # Every own_key_id-reading code path in this class (initiate(),
        # _handle_session_init_response()) is INITIATOR-only -- if that
        # ever stops being true, this None-for-responder contract breaks
        # silently, since Python won't catch it. Checked directly, not
        # assumed: grep every read of self._own_key_id before relying on
        # this if you're changing responder-side behavior.
        self.role = role
        self._own_key_id = own_key_id
        self._keys = key_lookup
        self.config = config or SessionConfig()

        self.state = SessionState.INITIAL
        self.cid: Optional[uuid.UUID] = None

        self._last_received: Optional[bytes] = None
        self._last_sent: Optional[bytes] = None
        self._attempt_count = 0
        self._deadline: Optional[float] = None

        self._outgoing_pdus: list = []
        self._outgoing_payloads: list = []

        # queued via post_payload, sent at next opportunity
        self._pending_payload: Optional[bytes] = None

        # Handshake-scoped secrets, populated as the exchange progresses.
        self._own_ephemeral_private = None
        self._own_ephemeral_public: Optional[KemPublicKey] = None
        self._peer_static_public: Optional[KemPublicKey] = None
        self._peer_key_id: Optional[KeyId] = None
        self._s1 = self._s2 = self._s3 = self._s4 = None
        self._n_a: Optional[bytes] = None
        self._n_b: Optional[bytes] = None
        self._chosen_aead: Optional[str] = None
        self._session_keys: Optional[SessionKeys] = None
        self._seq_a2b = 0
        self._seq_b2a = 0
        # initiator: what we encrypted into c_m
        self._sent_plaintext_for_h_m: Optional[bytes] = None

        self._incoming_queue: list = []

    # -- public: push in --------------------------------------------------

    def post_pdu(self, der_bytes: bytes) -> None:
        """Appends a received PDU to the incoming queue."""
        self._incoming_queue.append(bytes(der_bytes))

    def post_payload(self, payload: bytes) -> None:
        """Appends a plaintext payload to be sent at the next opportunity.
        
        The payload is sent in the next update() call that occurs while the session is ESTABLISHED.
        If the session is not yet established, the payload is queued until it can be sent. Raises
        ValueError if the payload is empty."""
        if not payload:
            # see EmptyFalseStartPayload / AEAD tag reasoning
            raise ValueError("payload must be non-empty")
        self._pending_payload = bytes(payload)

    # -- public: pull out ---------------------------------------------------

    def poll_pdu(self) -> bool:
        """Returns True if a PDU is ready to be sent, False otherwise."""
        return len(self._outgoing_pdus) > 0

    def get_pdu(self) -> bytes:
        """Returns the next PDU to be sent, removing it from the outgoing queue."""
        return self._outgoing_pdus.pop(0)

    def poll_payload(self) -> bool:
        """Returns True if a plaintext payload is ready to be sent, False otherwise."""
        return len(self._outgoing_payloads) > 0

    def get_payload(self) -> bytes:
        """Returns the next plaintext payload to be sent, removing it from the outgoing queue."""
        return self._outgoing_payloads.pop(0)

    def get_last_sent(self) -> Optional[bytes]:
        """Returns the last PDU this instance sent, or None if it has never
        sent anything. This is useful for testing and logging, but not
        needed for normal operation: the caller can always capture the
        bytes returned from get_pdu() instead."""
        return self._last_sent

    def get_last_received(self) -> Optional[bytes]:
        """Returns the last PDU this instance accepted, or None if it has
        never accepted anything. This is useful for testing and logging,
        but not needed for normal operation: the caller can always capture
        the bytes passed to post_pdu() instead."""
        return self._last_received

    # -- public: lifecycle -------------------------------------------------

    def initiate(self, peer_key_id: KeyId, now: float) -> None:
        """Initiates a handshake with the given peer identity. Only valid for
        an INITIATOR-role Session in the INITIAL state. Raises
        SessionError if called in any other state or role."""
        if self.role is not Role.INITIATOR:
            raise SessionError("only an INITIATOR-role Session can initiate()")
        if self.state is not SessionState.INITIAL:
            raise SessionError(f"cannot initiate() from state {self.state}")

        self.cid = uuid.uuid4()
        self._peer_key_id = peer_key_id
        peer_static_public = self._keys.get_public_key(peer_key_id)

        level = self.config.kem_level
        self._own_ephemeral_private, self._own_ephemeral_public = _generate_ephemeral(level)
        self._s1, ct1 = _encapsulate(peer_static_public)

        req = SessionInitRequest({
            "ct1": ct1,
            "key_id_b": peer_key_id,
            "pk_a_star": self._own_ephemeral_public,
            "key_id_a": self._own_key_id,
            "acceptable_aeads": AeadAlgorithmList.build(list(self.config.acceptable_aeads)),
        })
        msg = MakeMessage.build(self.cid, "session_init_request", req)
        der = msg.dump()

        self._last_sent = der
        self._attempt_count = 0
        self._deadline = now + self.config.retry_interval_seconds
        self.state = SessionState.EXPECT_SESSION_INIT_RESPONSE
        self._outgoing_pdus.append(der)

    def reset(self) -> None:
        """Equivalent of onApplicationReset -- drop everything and return
        to a state indistinguishable from a freshly constructed instance
        (except role/own_key_id/key_lookup/config, which don't change)."""
        role, own_key_id, keys, config = self.role, self._own_key_id, self._keys, self.config
        self.__init__(role, own_key_id, keys, config)  # type: ignore[misc] #pylint: disable=unnecessary-dunder-call

    def fork(self) -> "Session":
        """Create a sibling Session sharing this instance's
        pre-response handshake state (cid, own ephemeral keypair, s1,
        peer identity) but with its own independent output queues and
        response-processing state.

        Only valid while still EXPECT_SESSION_INIT_RESPONSE -- i.e.
        before any SessionInitResponse has been processed by this
        instance. This exists for exactly one reason: the same cid may
        have more than one plausible SessionInitResponse in flight (the
        real responder's, plus zero or more forged ones -- forging one
        requires no private key, only public keys already on the wire;
        see dispatcher.py and rationale.md). Since session.py's current
        design has a single Session own one linear state-machine
        path, trying more than one candidate response means giving each
        one its own sibling instance that starts from the identical
        pre-response state and diverges from there.

        The ephemeral private key is reconstructed from its raw seed
        bytes rather than copied by reference or deep-copied, matching
        this project's established pattern elsewhere (keystore.py's KEK
        handling, etc.) rather than relying on the cryptography library's
        undocumented copy/deepcopy support for its key objects.

        Any payload already queued via post_payload() before this fork
        was created is also copied, so a false-start payload queued
        before any response has arrived reaches every candidate spawned
        afterward, not just whichever candidate happens to be created
        first.
        """
        if self.role is not Role.INITIATOR:
            raise SessionError("only an INITIATOR-role Session can fork()")
        if self.state is not SessionState.EXPECT_SESSION_INIT_RESPONSE:
            raise SessionError("fork() is only valid before a response has been processed")

        twin = Session(self.role, self._own_key_id, self._keys, self.config)
        twin.state = SessionState.EXPECT_SESSION_INIT_RESPONSE
        twin.cid = self.cid
        twin._peer_key_id = self._peer_key_id #pylint: disable=protected-access
        twin._own_ephemeral_private = _MLKEM_PRIVATE_CLASSES[self.config.kem_level].from_seed_bytes( #pylint: disable=protected-access
            self._own_ephemeral_private.private_bytes_raw()
        )
        twin._own_ephemeral_public = self._own_ephemeral_public  #pylint: disable=protected-access
        twin._s1 = self._s1  #pylint: disable=protected-access
        twin._last_sent = self._last_sent  #pylint: disable=protected-access
        twin._attempt_count = self._attempt_count  #pylint: disable=protected-access
        twin._deadline = self._deadline  #pylint: disable=protected-access
        twin._pending_payload = self._pending_payload  #pylint: disable=protected-access
        return twin

    # -- public: the crank ---------------------------------------------------

    def update(self, now: float) -> Tuple[UpdateResult, float]:
        """Processes exactly one queued incoming PDU (if any), advances
        retry/TTL bookkeeping, and reports what's ready plus how long
        until update() should be called again even if nothing else
        happens. Call this after every post_*() and on your own timer
        using the returned duration."""
        if self.state is SessionState.DROPPED:
            return UpdateResult.SESSION_DROPPED, float("inf")

        if self._incoming_queue:
            incoming = self._incoming_queue.pop(0)
            self._process_incoming(incoming, now)

        if self.state is SessionState.ESTABLISHED and self._pending_payload is not None:
            self._send_established_payload(now)

        if self.state is SessionState.DROPPED:
            return UpdateResult.SESSION_DROPPED, float("inf")

        if self._deadline is not None and now >= self._deadline and self.state not in (
            SessionState.ESTABLISHED, SessionState.INITIAL,
        ):
            self._on_timeout(now)

        if self.state is SessionState.DROPPED:
            return UpdateResult.SESSION_DROPPED, float("inf")

        if self._deadline is not None:
            next_deadline = self._deadline
        else:
            next_deadline = now + self.config.retry_interval_seconds
        if self.poll_payload():
            return UpdateResult.PAYLOAD_READY, next_deadline
        if self.poll_pdu():
            return UpdateResult.PDU_READY, next_deadline
        return UpdateResult.NOTHING_READY, next_deadline

    # -- internal: retry/timeout --------------------------------------------

    def _on_timeout(self, now: float) -> None:
        if self.role is Role.RESPONDER:
            # Bob never retries -- he only ever reacts to Alice's retries.
            # His deadline is a pure TTL: past it, the candidate is
            # abandoned outright, no resend.
            self.state = SessionState.DROPPED
            return
        if self._attempt_count >= self.config.max_retries:
            self.state = SessionState.DROPPED
            return
        self._attempt_count += 1
        self._deadline = now + self.config.retry_interval_seconds
        if self._last_sent is not None:
            self._outgoing_pdus.append(self._last_sent)

    # -- internal: dispatch ---------------------------------------------------

    def _process_incoming(self, der_bytes: bytes, now: float) -> None:
        #pylint: disable=too-many-branches
        # Byte-exact duplicate of what we already accepted for the current
        # state: resend our cached reply verbatim, do not reprocess.
        if self._last_received is not None and der_bytes == self._last_received:
            if self._last_sent is not None:
                self._outgoing_pdus.append(self._last_sent)
            return

        try:
            msg = MakeMessage.load(der_bytes)
        except ValueError:
            # Malformed input is silently dropped, not an exception -- see
            # module docstring. ValueError, not just NonCanonicalEncoding/
            # InvalidCorrelationId: those two are for input that DOES parse
            # but fails a specific named check; input that doesn't even
            # parse as a MakeMessage SEQUENCE raises a plain ValueError
            # straight out of asn1crypto, and must be dropped the same way.
            return

        payload_name = msg["payload"].name
        incoming_cid = msg.correlation_id

        if self.state is SessionState.INITIAL and self.role is Role.RESPONDER:
            if payload_name != "session_init_request":
                return  # not a legal first message; silently ignored
            self.cid = incoming_cid
            self._handle_session_init_request(msg, der_bytes, now)
            return

        if incoming_cid != self.cid:
            return  # not this session

        if self.state is SessionState.EXPECT_SESSION_INIT_RESPONSE and self.role is Role.INITIATOR:
            if payload_name != "session_init_response":
                raise UnexpectedPDU(f"expected session_init_response, got {payload_name}")
            self._handle_session_init_response(msg, der_bytes, now)
        elif self.state is SessionState.EXPECT_SESSION_COMPLETION_REQUEST and self.role is Role.RESPONDER:
            if payload_name != "session_completion_request":
                raise UnexpectedPDU(f"expected session_completion_request, got {payload_name}")
            self._handle_session_completion_request(msg, der_bytes, now)
        elif self.state is SessionState.EXPECT_SESSION_COMPLETION_RESPONSE and self.role is Role.INITIATOR:
            if payload_name != "session_completion_response":
                raise UnexpectedPDU(f"expected session_completion_response, got {payload_name}")
            self._handle_session_completion_response(msg, der_bytes, now)
        elif self.state is SessionState.ESTABLISHED:
            if payload_name != "message":
                raise UnexpectedPDU(f"expected message, got {payload_name}")
            self._handle_established_message(msg)
        else:
            raise UnexpectedPDU(f"unexpected {payload_name} for role={self.role} state={self.state}")

    # -- internal: responder handlers -----------------------------------------

    def _handle_session_init_request(self, msg: MakeMessage, der_bytes: bytes, now: float) -> None:
        #pylint: disable=too-many-locals
        req = msg["payload"].chosen

        try:
            own_static_private = self._keys.get_private_key(req["key_id_b"])
        except Exception as e:
            raise HandshakeFailed(f"cannot resolve the requested recipient key: {e}") from e
        try:
            peer_static_public = self._keys.get_public_key(req["key_id_a"])
        except Exception as e:
            raise HandshakeFailed(f"unknown claimed sender identity: {e}") from e

        level = _level_of(req["pk_a_star"])
        s1 = _decapsulate(own_static_private, level, req["ct1"])

        own_ephemeral_private, own_ephemeral_public = _generate_ephemeral(level)
        s2, ct2 = _encapsulate(req["pk_a_star"])
        s3, ct3 = _encapsulate(peer_static_public)
        n_b = os.urandom(16)

        requested = set(req["acceptable_aeads"].native)
        chosen = next((name for name in self.config.acceptable_aeads if AEAD_OIDS[name] in requested), None)
        if chosen is None:
            raise HandshakeFailed("no mutually acceptable AEAD algorithm")

        resp = SessionInitResponse({
            "key_id_b": req["key_id_b"],
            "pk_b_star": own_ephemeral_public,
            "ct2": ct2,
            "ct3": ct3,
            "n_b": n_b,
            "chosen_aead": AEAD_OIDS[chosen],
        })
        out_msg = MakeMessage.build(self.cid, "session_init_response", resp)
        out_der = out_msg.dump()

        self._own_ephemeral_private = own_ephemeral_private
        self._own_ephemeral_public = own_ephemeral_public
        self._peer_static_public = peer_static_public
        self._peer_key_id = req["key_id_a"]
        self._s1, self._s2, self._s3 = s1, s2, s3
        self._n_b = n_b
        self._chosen_aead = chosen

        self._last_received = der_bytes
        self._last_sent = out_der
        self._attempt_count = 0
        self._deadline = now + self.config.ttl_seconds  # responder: TTL only, no retry
        self.state = SessionState.EXPECT_SESSION_COMPLETION_REQUEST
        self._outgoing_pdus.append(out_der)

    def _handle_session_completion_request(
        #pylint: disable=too-many-locals
        self,
        msg: MakeMessage,
        der_bytes: bytes,
        now: float,
        ) -> None:
        _ = now  # responder doesn't retry, so no deadline bookkeeping needed here
        req = msg["payload"].chosen
        level = self.config.kem_level
        s4 = _decapsulate(
            self._own_ephemeral_private.private_bytes_raw(), level, req["ct4"],
        )
        n_a = req["n_a"].native

        keys = derive_session_keys(
            n_a=n_a, n_b=self._n_b, f_a=self._peer_key_id.dump(),
            s1=self._s1, s2=self._s2, s3=self._s3, s4=s4, aead=self._chosen_aead,
        )

        try:
            plaintext = _decrypt(
                keys.aead_name, keys.key_a2b, keys.iv_a2b, seq=0,
                ciphertext=req["c_m"].native, associated_data=self.cid.bytes,
            )
        except Exception as e:
            # This is precisely the "forged candidate" case from the
            # threat model: a structurally valid message under a key
            # that doesn't actually correspond. Never send anything back
            # for this.
            raise HandshakeFailed("c_m did not decrypt -- unauthenticated candidate") from e

        if plaintext:
            self._outgoing_payloads.append(plaintext)
        h_m = hashlib.sha256(plaintext).digest()

        resp_fields = {"h_m": h_m}
        if self._pending_payload is not None:
            reply_ct = _encrypt(
                keys.aead_name, keys.key_b2a, keys.iv_b2a, seq=0,
                plaintext=self._pending_payload, associated_data=self.cid.bytes,
            )
            resp_fields["m"] = reply_ct
            self._seq_b2a = 1
            self._pending_payload = None

        resp = SessionCompletionResponse(resp_fields)
        out_msg = MakeMessage.build(self.cid, "session_completion_response", resp)
        out_der = out_msg.dump()

        self._n_a = n_a
        self._s4 = s4
        self._session_keys = keys
        self._seq_a2b = 1

        self._last_received = der_bytes
        self._last_sent = out_der
        self.state = SessionState.ESTABLISHED
        self._deadline = None
        self._outgoing_pdus.append(out_der)

    # -- internal: initiator handlers -----------------------------------------

    def _handle_session_init_response(self, msg: MakeMessage, der_bytes: bytes, now: float) -> None:
        #pylint: disable=too-many-locals
        resp = msg["payload"].chosen

        if not _key_id_equal(resp["key_id_b"], self._peer_key_id):
            raise HandshakeFailed("session_init_response key_id_b does not match the identity we addressed")

        level = self.config.kem_level
        own_static_private = self._keys.get_private_key(self._own_key_id)

        s2 = _decapsulate(self._own_ephemeral_private.private_bytes_raw(), level, resp["ct2"])
        s3 = _decapsulate(own_static_private, level, resp["ct3"])

        chosen = aead_name(resp["chosen_aead"].native)
        if chosen is None or chosen not in self.config.acceptable_aeads:
            raise HandshakeFailed(f"responder chose an unacceptable AEAD: {resp['chosen_aead'].native}")

        s4, ct4 = _encapsulate(resp["pk_b_star"])
        n_a = os.urandom(16)

        keys = derive_session_keys(
            n_a=n_a, n_b=resp["n_b"].native, f_a=self._own_key_id.dump(),
            s1=self._s1, s2=s2, s3=s3, s4=s4, aead=chosen,
        )

        plaintext = self._pending_payload if self._pending_payload is not None else b""
        c_m = _encrypt(
            keys.aead_name, keys.key_a2b, keys.iv_a2b, seq=0,
            plaintext=plaintext, associated_data=self.cid.bytes,
        )
        self._pending_payload = None

        req = SessionCompletionRequest.build(c_m=c_m, ct4=ct4, n_a=n_a)
        out_msg = MakeMessage.build(self.cid, "session_completion_request", req)
        out_der = out_msg.dump()

        self._n_a = n_a
        self._n_b = resp["n_b"].native
        self._chosen_aead = chosen
        self._session_keys = keys
        self._seq_a2b = 1
        self._sent_plaintext_for_h_m = plaintext

        self._last_received = der_bytes
        self._last_sent = out_der
        self._attempt_count = 0
        self._deadline = now + self.config.retry_interval_seconds
        self.state = SessionState.EXPECT_SESSION_COMPLETION_RESPONSE
        self._outgoing_pdus.append(out_der)

    def _handle_session_completion_response(self, msg: MakeMessage, der_bytes: bytes, now: float) -> None:
        _ = now  # initiator doesn't retry, so no deadline bookkeeping needed here
        resp = msg["payload"].chosen

        expected_h_m = hashlib.sha256(self._sent_plaintext_for_h_m).digest()
        if not hmac.compare_digest(resp["h_m"].native, expected_h_m):
            raise HandshakeFailed("h_m does not match -- unauthenticated candidate")

        if resp["m"].native is not None:
            try:
                reply_plaintext = _decrypt(
                    self._session_keys.aead_name, self._session_keys.key_b2a, self._session_keys.iv_b2a,
                    seq=0, ciphertext=resp["m"].native, associated_data=self.cid.bytes,
                )
            except Exception as e:
                raise HandshakeFailed("m did not decrypt despite matching h_m") from e
            self._seq_b2a = 1
            self._outgoing_payloads.append(reply_plaintext)

        self._last_received = der_bytes
        self._last_sent = None
        self.state = SessionState.ESTABLISHED
        self._deadline = None

    # -- internal: established-session traffic --------------------------------

    def _send_established_payload(self, now: float) -> None:
        _ = now  # initiator doesn't retry, so no deadline bookkeeping needed here
        payload = self._pending_payload
        self._pending_payload = None
        if self.role is Role.INITIATOR:
            seq = self._seq_a2b
            ct = _encrypt(
                self._session_keys.aead_name, self._session_keys.key_a2b, self._session_keys.iv_a2b,
                seq=seq, plaintext=payload, associated_data=self.cid.bytes,
            )
            self._seq_a2b += 1
        else:
            seq = self._seq_b2a
            ct = _encrypt(
                self._session_keys.aead_name, self._session_keys.key_b2a, self._session_keys.iv_b2a,
                seq=seq, plaintext=payload, associated_data=self.cid.bytes,
            )
            self._seq_b2a += 1

        msg_pdu = Message({"seq": seq, "m": ct})
        out_msg = MakeMessage.build(self.cid, "message", msg_pdu)
        self._outgoing_pdus.append(out_msg.dump())

    def _handle_established_message(self, msg: MakeMessage) -> None:
        inner = msg["payload"].chosen
        seq = inner["seq"].native
        ct = inner["m"].native

        # Incoming direction is the opposite of our own outgoing direction.
        if self.role is Role.INITIATOR:
            expected_seq = self._seq_b2a
            key, iv = self._session_keys.key_b2a, self._session_keys.iv_b2a
        else:
            expected_seq = self._seq_a2b
            key, iv = self._session_keys.key_a2b, self._session_keys.iv_a2b

        if seq != expected_seq:
            # Strict monotonic sequencing only -- not a full replay
            # window. Flagged as an extension point, not solved here.
            raise HandshakeFailed(f"unexpected seq {seq}, expected {expected_seq}")

        plaintext = _decrypt(
            self._session_keys.aead_name, key, iv, seq=seq,
            ciphertext=ct, associated_data=self.cid.bytes,
        )

        if self.role is Role.INITIATOR:
            self._seq_b2a += 1
        else:
            self._seq_a2b += 1

        self._outgoing_payloads.append(plaintext)


def _key_id_equal(a: KeyId, b: KeyId) -> bool:
    return (
        a["hash_algorithm"]["algorithm"].dotted == b["hash_algorithm"]["algorithm"].dotted
        and hmac.compare_digest(a["key_hash"].native, b["key_hash"].native)
    )
