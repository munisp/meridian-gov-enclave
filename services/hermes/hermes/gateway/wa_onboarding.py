"""WhatsApp TIN-binding onboarding + Redis-backed channel stores.

Closes the empty-user-token residual on the WhatsApp channel: before a
wa_id may use TIN-scoped tools it must bind to a TIN via an OTP challenge.

- TIN validation: format NNNNNNNN-NNNN (12 digits) with a weighted mod-11
  check digit in the 12th position, mirroring the local validator in
  services/wht (that service is not part of this enclave clone, so the
  algorithm is replicated here and pinned by tests).
- OTP: 6-digit code, 10-minute TTL, 3 attempts then lockout. Delivery goes
  through the OtpSender protocol (notification-service seam); the default
  SimOtpSender logs the code with an honest [SIM] tag when no notification
  service is wired.
- Binding record: {wa_id, tin, consent_ref, ts} with an NDPA consent note;
  consent_ref is an opaque reference to the consent artefact.
- Session token: on successful binding a scoped session token is minted via
  the TokenIssuer seam and attached to the AgentLoop UserContext so tool
  calls execute user-scoped (no more empty token). The default
  SimTokenIssuer returns a `wa-sim-*` token; PRODUCTION MUST wire a
  KeycloakTokenIssuer that exchanges the verified binding for a real
  Keycloak token via the identity service (token-exchange grant). The seam
  is wired here; the exchange itself is SIM.
- Stores: binding / session / message-id dedup are behind small protocols
  with in-memory + Redis implementations. When REDIS_URL is unset or
  unreachable the channel falls back to in-memory with an honest log line.
  TTLs: session 24h (matches agent/memory.py), dedup 48h.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

log = logging.getLogger("hermes.whatsapp")

# ---------------------------------------------------------------------------
# TIN validation (mirrors services/wht local validator)
# ---------------------------------------------------------------------------
TIN_RE = re.compile(r"^\d{8}-\d{4}$")
_CHECK_WEIGHTS = (3, 5, 7, 2, 4, 6, 8, 9, 3, 5, 7)  # over the first 11 digits


def compute_tin_check_digit(eleven_digits: str) -> int:
    """Weighted mod-11 check digit over the first 11 digits (12th position)."""
    total = sum(int(d) * w for d, w in zip(eleven_digits, _CHECK_WEIGHTS))
    return (11 - (total % 11)) % 10


def valid_tin(tin: str) -> bool:
    """Format NNNNNNNN-NNNN + check digit (digit 12)."""
    if not tin or not TIN_RE.match(tin):
        return False
    digits = tin.replace("-", "")
    return compute_tin_check_digit(digits[:11]) == int(digits[11])


def mask_tin(tin: str) -> str:
    """Mask for STATUS display: keep first 2 + last 2 digits, hide the rest."""
    digits = tin.replace("-", "")
    if len(digits) < 8:
        return "*" * len(tin)
    return f"{digits[:2]}{'*' * 6}-{'*' * 2}{digits[-2:]}"


# ---------------------------------------------------------------------------
# OTP challenge
# ---------------------------------------------------------------------------
@dataclass
class OtpChallenge:
    tin: str
    code_hash: str
    expires_at: float
    attempts: int = 0


def _hash_code(wa_id: str, code: str) -> str:
    import hashlib
    return hashlib.sha256(f"wa-otp:{wa_id}:{code}".encode()).hexdigest()


class OtpManager:
    """6-digit OTP, TTL (default 10 min), max attempts (default 3)."""

    def __init__(self, ttl_s: int = 600, max_attempts: int = 3,
                 code_factory=None):
        self.ttl_s = ttl_s
        self.max_attempts = max_attempts
        self._code_factory = code_factory or (lambda: f"{secrets.randbelow(1000000):06d}")
        self._pending: dict[str, OtpChallenge] = {}

    def start(self, wa_id: str, tin: str) -> str:
        """Issue a fresh challenge; returns the code (for the sender)."""
        code = self._code_factory()
        self._pending[wa_id] = OtpChallenge(
            tin=tin, code_hash=_hash_code(wa_id, code),
            expires_at=time.time() + self.ttl_s)
        return code

    def pending(self, wa_id: str) -> Optional[OtpChallenge]:
        ch = self._pending.get(wa_id)
        if ch and time.time() > ch.expires_at:
            self._pending.pop(wa_id, None)
            return None
        return ch

    def cancel(self, wa_id: str) -> None:
        self._pending.pop(wa_id, None)

    def verify(self, wa_id: str, code: str) -> str:
        """Returns: ok | wrong | expired | locked | no_challenge."""
        ch = self._pending.get(wa_id)
        if ch is None:
            return "no_challenge"
        if time.time() > ch.expires_at:
            self._pending.pop(wa_id, None)
            return "expired"
        if ch.attempts >= self.max_attempts:
            self._pending.pop(wa_id, None)
            return "locked"
        if secrets.compare_digest(ch.code_hash, _hash_code(wa_id, code.strip())):
            self._pending.pop(wa_id, None)
            return "ok"
        ch.attempts += 1
        if ch.attempts >= self.max_attempts:
            self._pending.pop(wa_id, None)
            return "locked"
        return "wrong"


class OtpSender(Protocol):
    """Notification-service seam for OTP delivery (SMS/WhatsApp)."""
    def send_otp(self, wa_id: str, code: str, ttl_s: int) -> None: ...


class SimOtpSender:
    """[SIM] OTP delivery: logs the code; no real message is sent. Use when
    no notification-service client is wired (dev/tests)."""

    def send_otp(self, wa_id: str, code: str, ttl_s: int) -> None:
        log.info("[SIM] otp delivery wa_id=%s code=%s ttl_s=%d "
                 "(no notification service configured)", wa_id, code, ttl_s)


# ---------------------------------------------------------------------------
# Scoped session token (identity-service seam)
# ---------------------------------------------------------------------------
class TokenIssuer(Protocol):
    """Mints a scoped session token for a verified wa_id<->TIN binding.

    PRODUCTION: implement KeycloakTokenIssuer which exchanges the verified
    binding for a real Keycloak access token via the identity service
    (token-exchange grant, audience = platform APIs, scope = the bound TIN).
    The exchange is intentionally a seam here; the default is SIM."""

    def issue(self, wa_id: str, tin: str) -> str: ...


class SimTokenIssuer:
    """[SIM] token: honest prefix so it can never be confused with a real JWT."""

    def issue(self, wa_id: str, tin: str) -> str:
        token = f"wa-sim-{uuid.uuid4().hex}"
        log.info("[SIM] scoped session token issued for wa_id=%s tin=%s "
                 "(production: exchange via identity service for Keycloak token)",
                 wa_id, mask_tin(tin))
        return token


# ---------------------------------------------------------------------------
# Binding store (wa_id -> TIN binding, persistent)
# ---------------------------------------------------------------------------
@dataclass
class Binding:
    wa_id: str
    tin: str
    consent_ref: str
    ts: float
    token: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"wa_id": self.wa_id, "tin": self.tin,
                "consent_ref": self.consent_ref, "ts": self.ts,
                "token": self.token, "note": self.note}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Binding":
        return Binding(wa_id=d["wa_id"], tin=d["tin"],
                       consent_ref=d["consent_ref"], ts=float(d["ts"]),
                       token=d.get("token", ""), note=d.get("note", ""))


NDPA_CONSENT_NOTE = (
    "NDPA consent: user initiated TIN binding over WhatsApp and completed "
    "OTP verification; consent covers processing of the wa_id<->TIN binding "
    "for taxpayer-copilot service delivery. Withdrawal: send UNLINK.")


def new_binding(wa_id: str, tin: str, token: str) -> Binding:
    return Binding(wa_id=wa_id, tin=tin,
                   consent_ref=f"ndpa-consent-{uuid.uuid4().hex[:16]}",
                   ts=time.time(), token=token, note=NDPA_CONSENT_NOTE)


class BindingStore(Protocol):
    def get(self, wa_id: str) -> Optional[Binding]: ...
    def put(self, binding: Binding) -> None: ...
    def delete(self, wa_id: str) -> None: ...


class MemoryBindingStore:
    def __init__(self):
        self._data: dict[str, Binding] = {}

    def get(self, wa_id: str) -> Optional[Binding]:
        return self._data.get(wa_id)

    def put(self, binding: Binding) -> None:
        self._data[binding.wa_id] = binding

    def delete(self, wa_id: str) -> None:
        self._data.pop(wa_id, None)


class RedisBindingStore:
    PREFIX = "hermes:wa:binding:"

    def __init__(self, client):
        self._r = client

    def get(self, wa_id: str) -> Optional[Binding]:
        raw = self._r.get(self.PREFIX + wa_id)
        return Binding.from_dict(json.loads(raw)) if raw else None

    def put(self, binding: Binding) -> None:
        self._r.set(self.PREFIX + binding.wa_id, json.dumps(binding.to_dict()))

    def delete(self, wa_id: str) -> None:
        self._r.delete(self.PREFIX + wa_id)


# ---------------------------------------------------------------------------
# Session store (wa_id -> session state, TTL 24h like agent/memory.py)
# ---------------------------------------------------------------------------
class SessionStore(Protocol):
    def get(self, wa_id: str) -> Optional[dict[str, Any]]: ...
    def put(self, wa_id: str, state: dict[str, Any]) -> None: ...
    def delete(self, wa_id: str) -> None: ...


class MemorySessionStore:
    def __init__(self, ttl_s: int = 24 * 3600):
        self.ttl_s = ttl_s
        self._data: dict[str, tuple[float, dict[str, Any]]] = {}

    def get(self, wa_id: str) -> Optional[dict[str, Any]]:
        item = self._data.get(wa_id)
        if item is None:
            return None
        ts, state = item
        if time.time() - ts > self.ttl_s:
            self._data.pop(wa_id, None)
            return None
        return state

    def put(self, wa_id: str, state: dict[str, Any]) -> None:
        self._data[wa_id] = (time.time(), dict(state))

    def delete(self, wa_id: str) -> None:
        self._data.pop(wa_id, None)


class RedisSessionStore:
    PREFIX = "hermes:wa:sess:"

    def __init__(self, client, ttl_s: int = 24 * 3600):
        self._r = client
        self.ttl_s = ttl_s

    def get(self, wa_id: str) -> Optional[dict[str, Any]]:
        raw = self._r.get(self.PREFIX + wa_id)
        return json.loads(raw) if raw else None

    def put(self, wa_id: str, state: dict[str, Any]) -> None:
        self._r.set(self.PREFIX + wa_id, json.dumps(state), ex=self.ttl_s)

    def delete(self, wa_id: str) -> None:
        self._r.delete(self.PREFIX + wa_id)


# ---------------------------------------------------------------------------
# Message-id dedup store (TTL 48h)
# ---------------------------------------------------------------------------
class DedupStore(Protocol):
    def is_new(self, mid: str) -> bool: ...


class MemoryDedupStore:
    """Bounded in-memory dedup set (previous _SeenIds behaviour)."""

    def __init__(self, capacity: int = 4096):
        self.capacity = capacity
        self._ids: list[str] = []
        self._set: set[str] = set()

    def is_new(self, mid: str) -> bool:
        if not mid:
            return True
        if mid in self._set:
            return False
        self._set.add(mid)
        self._ids.append(mid)
        if len(self._ids) > self.capacity:
            self._set.discard(self._ids.pop(0))
        return True


class RedisDedupStore:
    """SET NX PX: survives process restarts; ids expire after ttl (48h)."""

    PREFIX = "hermes:wa:dedup:"

    def __init__(self, client, ttl_s: int = 48 * 3600):
        self._r = client
        self.ttl_ms = ttl_s * 1000

    def is_new(self, mid: str) -> bool:
        if not mid:
            return True
        return self._r.set(self.PREFIX + mid, "1", nx=True, px=self.ttl_ms) is not None


# ---------------------------------------------------------------------------
# Builders: Redis when reachable, honest in-memory fallback otherwise
# ---------------------------------------------------------------------------
def _redis_client(redis_url: str):
    import redis  # type: ignore  # optional dependency
    client = redis.Redis.from_url(redis_url, decode_responses=True,
                                  socket_connect_timeout=2, socket_timeout=2)
    client.ping()
    return client


@dataclass
class WaStores:
    binding: BindingStore = field(default_factory=MemoryBindingStore)
    sessions: SessionStore = field(default_factory=MemorySessionStore)
    dedup: DedupStore = field(default_factory=MemoryDedupStore)
    backend: str = "memory"


def build_wa_stores(redis_url: str = "", session_ttl_s: int = 24 * 3600,
                    dedup_ttl_s: int = 48 * 3600, client=None) -> WaStores:
    """Redis-backed stores when REDIS_URL is set and reachable (or a client
    is injected); otherwise in-memory with an honest log line."""
    if client is None and redis_url:
        try:
            client = _redis_client(redis_url)
        except Exception as e:  # noqa: BLE001 - fallback must be total
            log.warning("hermes whatsapp: REDIS_URL set but unreachable (%s); "
                        "falling back to in-memory session/dedup/binding stores",
                        type(e).__name__)
            client = None
    if client is not None:
        log.info("hermes whatsapp: using Redis stores (session TTL %ds, "
                 "dedup TTL %ds)", session_ttl_s, dedup_ttl_s)
        return WaStores(binding=RedisBindingStore(client),
                        sessions=RedisSessionStore(client, session_ttl_s),
                        dedup=RedisDedupStore(client, dedup_ttl_s),
                        backend="redis")
    if not redis_url:
        log.info("hermes whatsapp: REDIS_URL unset; in-memory "
                 "session/dedup/binding stores (non-durable across restarts)")
    return WaStores(binding=MemoryBindingStore(),
                    sessions=MemorySessionStore(session_ttl_s),
                    dedup=MemoryDedupStore(), backend="memory")
