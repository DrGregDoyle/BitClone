"""Authentication, origin checks, rate limits, redaction, and API auditing."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Callable, Iterable

from src.api.service import APIError


ALL_SCOPES = frozenset({"read", "events", "admin"})
SENSITIVE_KEY_PARTS = (
    "cookie",
    "credential",
    "mnemonic",
    "passphrase",
    "password",
    "private_key",
    "secret",
    "seed",
    "token",
)


def generate_api_token() -> str:
    """Return a high-entropy opaque bearer token."""
    return secrets.token_urlsafe(32)


def redact_secrets(value: Any) -> Any:
    """Recursively redact fields whose names indicate secret material."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    credential_id: str
    scopes: frozenset[str]


@dataclass(frozen=True, slots=True)
class APICredential:
    credential_id: str
    token_digest: bytes
    scopes: frozenset[str]

    @classmethod
    def from_token(
            cls,
            credential_id: str,
            token: str,
            scopes: Iterable[str] = ALL_SCOPES,
    ) -> "APICredential":
        normalized_scopes = frozenset(scopes)
        unknown = normalized_scopes - ALL_SCOPES
        if unknown:
            raise ValueError(f"Unsupported API scopes: {sorted(unknown)}")
        if not token:
            raise ValueError("API token cannot be empty")
        return cls(
            credential_id=credential_id,
            token_digest=hashlib.sha256(token.encode("utf-8")).digest(),
            scopes=normalized_scopes,
        )


class BearerAuthenticator:
    """Validate opaque bearer tokens without retaining their plaintext."""

    def __init__(self, credentials: Iterable[APICredential]):
        self._credentials = tuple(credentials)
        if not self._credentials:
            raise ValueError("At least one API credential is required")

    def authenticate(
            self,
            authorization: str | None,
            required_scope: str | None,
    ) -> AuthenticatedPrincipal | None:
        if required_scope is None:
            return None
        if authorization is None:
            raise APIError(401, "authentication_required", "A bearer token is required")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            raise APIError(
                401,
                "invalid_authorization",
                "Authorization must use the Bearer scheme",
            )

        candidate = hashlib.sha256(token.encode("utf-8")).digest()
        credential = next(
            (
                item
                for item in self._credentials
                if hmac.compare_digest(candidate, item.token_digest)
            ),
            None,
        )
        if credential is None:
            raise APIError(401, "invalid_token", "The bearer token is invalid")
        if required_scope not in credential.scopes and "admin" not in credential.scopes:
            raise APIError(
                403,
                "insufficient_scope",
                f"The bearer token lacks the required '{required_scope}' scope",
            )
        return AuthenticatedPrincipal(credential.credential_id, credential.scopes)


class OriginPolicy:
    """Permit non-browser clients and an explicit set of browser origins."""

    def __init__(self, allowed_origins: Iterable[str]):
        self.allowed_origins = frozenset(origin.rstrip("/") for origin in allowed_origins)

    def validate(self, origin: str | None) -> str | None:
        if origin is None:
            return None
        normalized = origin.rstrip("/")
        if normalized not in self.allowed_origins:
            raise APIError(403, "origin_not_allowed", "The request origin is not allowed")
        return normalized


class SlidingWindowRateLimiter:
    """Small in-memory fixed-window limiter keyed by client and credential."""

    def __init__(
            self,
            limit: int = 120,
            window_seconds: float = 60.0,
            clock: Callable[[], float] = time.monotonic,
    ):
        if limit < 1 or window_seconds <= 0:
            raise ValueError("Rate-limit values must be positive")
        self.limit = limit
        self.window_seconds = float(window_seconds)
        self._clock = clock
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> int:
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - requests[0])) + 1)
                raise APIError(
                    429,
                    "rate_limit_exceeded",
                    "The API request rate limit was exceeded",
                    {"retry_after_seconds": retry_after},
                )
            requests.append(now)
            return self.limit - len(requests)


class AuditRecorder:
    """Append security-relevant API events as redacted JSON lines."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.records: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields: Any) -> None:
        record = redact_secrets(
            {
                "timestamp": datetime.now(tz=timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z"),
                "event": event,
                **fields,
            }
        )
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self.records.append(record)
            if self.path is None:
                return
            descriptor = os.open(
                self.path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, f"{line}\n".encode("utf-8"))
            finally:
                os.close(descriptor)
