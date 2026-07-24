"""Minimal authenticated JSON-RPC client for a Bitcoin Core block source."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

__all__ = ["BitcoinCoreRPC", "BitcoinCoreRPCError"]


class BitcoinCoreRPCError(RuntimeError):
    """Raised when Bitcoin Core rejects or cannot complete an RPC request."""


class BitcoinCoreRPC:
    def __init__(
            self,
            url: str,
            username: str | None = None,
            password: str | None = None,
            cookie_file: str | Path | None = None,
            timeout: float = 10.0,
    ) -> None:
        if not url:
            raise ValueError("Bitcoin Core RPC URL is required")
        if urlparse(url).scheme not in {"http", "https"}:
            raise ValueError("Bitcoin Core RPC URL must use http or https")
        if timeout <= 0:
            raise ValueError("Bitcoin Core RPC timeout must be positive")
        self.url = url
        self.username = username
        self._password = password
        self.cookie_file = Path(cookie_file).expanduser() if cookie_file is not None else None
        self.timeout = timeout
        self._request_id = 0

    def call(self, method: str, *params):
        self._request_id += 1
        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": self._request_id,
            "method": method,
            "params": list(params),
        }).encode("utf-8")
        request = Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": self._authorization_header(),
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise BitcoinCoreRPCError(f"Bitcoin Core RPC HTTP {error.code}: {detail}") from error
        except (URLError, TimeoutError, OSError) as error:
            raise BitcoinCoreRPCError(f"Bitcoin Core RPC unavailable: {error}") from error
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BitcoinCoreRPCError("Bitcoin Core RPC returned invalid JSON") from error

        if result.get("error") is not None:
            error = result["error"]
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise BitcoinCoreRPCError(f"Bitcoin Core RPC error {code}: {message}")
        return result.get("result")

    def get_blockchain_info(self) -> dict:
        return self.call("getblockchaininfo")

    def get_block_hash(self, height: int) -> bytes:
        display_hash = self.call("getblockhash", height)
        return bytes.fromhex(display_hash)[::-1]

    def get_block(self, block_hash: bytes) -> bytes:
        raw_hex = self.call("getblock", block_hash[::-1].hex(), 0)
        return bytes.fromhex(raw_hex)

    def get_block_header(self, block_hash: bytes) -> bytes:
        raw_hex = self.call("getblockheader", block_hash[::-1].hex(), False)
        return bytes.fromhex(raw_hex)

    def _authorization_header(self) -> str:
        username, password = self._credentials()
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    def _credentials(self) -> tuple[str, str]:
        if self.cookie_file is not None:
            try:
                value = self.cookie_file.read_text(encoding="utf-8").strip()
            except OSError as error:
                raise BitcoinCoreRPCError(f"Cannot read Bitcoin Core RPC cookie: {error}") from error
            if ":" not in value:
                raise BitcoinCoreRPCError("Bitcoin Core RPC cookie is malformed")
            return tuple(value.split(":", 1))
        if self.username is None or self._password is None:
            raise BitcoinCoreRPCError(
                "Bitcoin Core RPC credentials require username/password or a cookie file"
            )
        return self.username, self._password
