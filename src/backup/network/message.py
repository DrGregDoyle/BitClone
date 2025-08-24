"""
Base classes for Bitcoin protocol messages (BitClone)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from io import BytesIO
from typing import Any, Iterable

from src.backup.data import Serializable, Header, MAINNET

__all__ = ["Message", "EmptyMessage"]

MB = MAINNET.magic


# --- helpers ---------------------------------------------------------------

def _to_display(v: Any) -> Any:
    """
    Normalize values for payload_dict():
      - bytes -> hex
      - Serializable -> to_dict()
      - IntFlag/Enum -> .name (with .value fallback)
      - iterables -> list of normalized items
      - IPv6/IPv4 objects -> str(...)
    """
    # bytes
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()

    # Serializable
    if isinstance(v, Serializable):
        return v.to_dict()

    # Enum / IntFlag (e.g., NodeType)
    # noinspection PyBroadException
    try:
        import enum  # local to keep dependencies light
        if isinstance(v, enum.Enum):
            # Prefer .name, fall back to .value for unknown/mixed flags
            if hasattr(v, "name"):
                return v.name
            return v.value
    except Exception:
        pass

    # IPvX address types: defer import to avoid hard dep here
    # noinspection PyBroadException
    try:
        import ipaddress as _ip
        if isinstance(v, (_ip.IPv4Address, _ip.IPv6Address)):
            return str(v)
    except Exception:  # noqa: B902
        pass

    # iterables (but not str/bytes handled above)
    if isinstance(v, Iterable) and not isinstance(v, (str, bytes, bytearray, memoryview)):
        return [_to_display(x) for x in v]

    return v


# --- core ------------------------------------------------------------------

class Message(Serializable, ABC):
    """
    All Bitcoin P2P messages inherit from this.
    """
    _registry: dict[str, type["Message"]] = {}

    # Subclasses may override:
    IS_DATA: bool = True  # control messages set this to False

    __slots__ = ("magic_bytes", "is_data", "_built_header", "_built_payload", "_built_command")

    def __init__(self, is_data: bool | None = None):
        # Magic bytes are fixed per-network at object creation
        self.magic_bytes = MB
        # If caller passes explicit is_data, honor it; otherwise use subclass default
        self.is_data = self.IS_DATA if is_data is None else bool(is_data)

        # Build cache (per-instance, invalidated by new instance only; we assume messages are immutable after init)
        self._built_header: Header | None = None
        self._built_payload: bytes | None = None
        self._built_command: str | None = None

    # ---- subclass bookkeeping

    def __init_subclass__(cls, **kw):
        """
        Called automatically when a subclass of Message is defined.
        Used here to auto-register new message classes by their COMMAND string, so they can be looked up later without
        manual bookkeeping.
        """
        super().__init_subclass__(**kw)
        cmd = getattr(cls, "COMMAND", None)
        if cmd:
            Message._registry[cmd] = cls

    # --- abstract hooks -----------------------------------------------------

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO):
        """Deserialize an instance from raw payload bytes."""
        raise NotImplementedError(f"{cls.__name__} must implement from_bytes()")

    @classmethod
    def from_payload(cls, byte_stream: bytes | BytesIO):
        return cls.from_bytes(byte_stream)

    @abstractmethod
    def payload(self) -> bytes:
        """Return just the payload bytes (no header)."""
        raise NotImplementedError(f"{self.__name__} must implement payload()")

    def payload_dict(self) -> dict:
        """
        Use the __slots__ to get the names for the dict
        """
        if hasattr(self, "__slots__"):
            names = tuple(n for n in self.__slots__ if not n.startswith("_"))
        else:
            names = tuple(k for k in self.__dict__ if not k.startswith("_"))

        d: dict[str, Any] = {}
        for name in names:
            # Support nested attr paths like "remote_net_addr.port" (optional nicety)
            obj: Any = self
            for part in name.split("."):
                obj = getattr(obj, part)
            d[name.split(".")[-1]] = _to_display(obj)
        return d

    # --- building / caching -------------------------------------------------

    def build(self) -> tuple[Header, bytes]:
        """
        Compute (header, payload) once. Subsequent calls reuse cached pair.
        Assumes instances are effectively immutable after construction.
        """
        # If COMMAND is dynamic on some subclass, we capture it here too
        command = getattr(self.__class__, "COMMAND")
        if (self._built_header is not None and
                self._built_payload is not None and
                self._built_command == command):
            return self._built_header, self._built_payload

        payload = self.payload()
        hdr = Header.from_payload(payload=payload, command=command, magic_bytes=self.magic_bytes)
        self._built_payload = payload
        self._built_header = hdr
        self._built_command = command
        return hdr, payload

    # --- Serializable API ---------------------------------------------------

    def header(self) -> Header:
        hdr, _ = self.build()
        return hdr

    def to_bytes(self) -> bytes:
        hdr, pl = self.build()
        return hdr.to_bytes() + pl

    def to_dict(self) -> dict:
        hdr, _ = self.build()
        return {
            "header": hdr.to_dict(),
            "payload": self.payload_dict(),
            "type": "data" if self.is_data else "control",
        }

    @property
    def message(self) -> bytes:
        return self.to_bytes()

    # --- registry helpers ---------------------------------------------------

    @classmethod
    def get_registered(cls, command: str):
        return cls._registry.get(command)


class EmptyMessage(Message):
    """
    Empty Message for various message types
    """
    __slots__ = ()

    def __init__(self):
        super().__init__()

    @classmethod
    def from_bytes(cls, byte_stream: bytes | BytesIO = b''):
        return cls()

    def payload(self) -> bytes:
        return b''
