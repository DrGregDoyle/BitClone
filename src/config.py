"""
Configuration and data-directory paths for BitClone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address
from pathlib import Path
import tomllib
from typing import Any

from src.core.network_profiles import NetworkName, NetworkProfile, get_network_profile


DEFAULT_DATA_DIR = Path.home() / ".bitclone"
CONFIG_FILENAME = "bitclone.toml"
MIN_PRUNE_KEEP_BLOCKS = 288


class BlockStorageMode(str, Enum):
    ARCHIVAL = "archival"
    PRUNED = "pruned"
    BITCOIN_CORE_REMOTE = "bitcoin-core-remote"


@dataclass(frozen=True, slots=True)
class BitCloneConfig:
    data_dir: Path = DEFAULT_DATA_DIR
    network: NetworkName = NetworkName.MAINNET
    db_path_override: Path | None = None
    upstream_host: str | None = None
    upstream_port: int | None = None
    block_storage: BlockStorageMode = BlockStorageMode.ARCHIVAL
    prune_keep_blocks: int = MIN_PRUNE_KEEP_BLOCKS
    core_rpc_url: str | None = None
    core_rpc_user: str | None = None
    core_rpc_password: str | None = field(default=None, repr=False, compare=False)
    core_rpc_cookie: Path | None = None
    core_rpc_timeout: float = 10.0
    api_host: str = "127.0.0.1"
    api_port: int = 8334
    api_allowed_origins: tuple[str, ...] = ()
    api_tls_cert: Path | None = None
    api_tls_key: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_options(
            cls,
            data_dir: str | Path | None = None,
            network: str | NetworkName = NetworkName.MAINNET,
            db_path: str | Path | None = None,
            upstream_host: str | None = None,
            upstream_port: int | None = None,
            block_storage: str | BlockStorageMode = BlockStorageMode.ARCHIVAL,
            prune_keep_blocks: int = MIN_PRUNE_KEEP_BLOCKS,
            core_rpc_url: str | None = None,
            core_rpc_user: str | None = None,
            core_rpc_password: str | None = None,
            core_rpc_cookie: str | Path | None = None,
            core_rpc_timeout: float = 10.0,
            api_host: str = "127.0.0.1",
            api_port: int = 8334,
            api_allowed_origins: list[str] | tuple[str, ...] | None = None,
            api_tls_cert: str | Path | None = None,
            api_tls_key: str | Path | None = None,
    ) -> "BitCloneConfig":
        if upstream_port is not None and not 1 <= upstream_port <= 65535:
            raise ValueError("upstream_port must be between 1 and 65535")
        storage_mode = (
            block_storage
            if isinstance(block_storage, BlockStorageMode)
            else BlockStorageMode(block_storage)
        )
        if prune_keep_blocks < 1:
            raise ValueError("prune_keep_blocks must be at least 1")
        if storage_mode is BlockStorageMode.PRUNED and prune_keep_blocks < MIN_PRUNE_KEEP_BLOCKS:
            raise ValueError(
                f"pruned storage must retain at least {MIN_PRUNE_KEEP_BLOCKS} recent blocks"
            )
        if storage_mode is BlockStorageMode.BITCOIN_CORE_REMOTE and not core_rpc_url:
            raise ValueError("bitcoin-core-remote storage requires core_rpc_url")
        if core_rpc_timeout <= 0:
            raise ValueError("core_rpc_timeout must be positive")
        if not 1 <= api_port <= 65535:
            raise ValueError("api_port must be between 1 and 65535")
        if (api_tls_cert is None) != (api_tls_key is None):
            raise ValueError("api_tls_cert and api_tls_key must be configured together")
        normalized_origins = tuple(api_allowed_origins or ())
        if any(not origin.startswith(("http://", "https://")) for origin in normalized_origins):
            raise ValueError("Every API allowed origin must begin with http:// or https://")
        try:
            loopback_api = ip_address(api_host).is_loopback
        except ValueError:
            loopback_api = api_host.lower() == "localhost"
        if not loopback_api and api_tls_cert is None:
            raise ValueError("Non-loopback API binding requires TLS")
        if not loopback_api and not normalized_origins:
            raise ValueError("Non-loopback API binding requires api_allowed_origins")
        network_name = network if isinstance(network, NetworkName) else NetworkName(network)
        db_path_override = Path(db_path).expanduser() if db_path is not None else None
        if data_dir is not None:
            resolved_data_dir = Path(data_dir).expanduser()
        elif db_path_override is not None:
            resolved_data_dir = db_path_override.parent
        else:
            resolved_data_dir = DEFAULT_DATA_DIR
        return cls(
            data_dir=resolved_data_dir,
            network=network_name,
            db_path_override=db_path_override,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            block_storage=storage_mode,
            prune_keep_blocks=prune_keep_blocks,
            core_rpc_url=core_rpc_url,
            core_rpc_user=core_rpc_user,
            core_rpc_password=core_rpc_password,
            core_rpc_cookie=Path(core_rpc_cookie).expanduser() if core_rpc_cookie is not None else None,
            core_rpc_timeout=core_rpc_timeout,
            api_host=api_host,
            api_port=api_port,
            api_allowed_origins=normalized_origins,
            api_tls_cert=Path(api_tls_cert).expanduser() if api_tls_cert is not None else None,
            api_tls_key=Path(api_tls_key).expanduser() if api_tls_key is not None else None,
        )

    @classmethod
    def from_toml(
            cls,
            data_dir: str | Path | None = None,
            network: str | NetworkName | None = None,
            db_path: str | Path | None = None,
            upstream_host: str | None = None,
            upstream_port: int | None = None,
            block_storage: str | BlockStorageMode | None = None,
            prune_keep_blocks: int | None = None,
            core_rpc_url: str | None = None,
            core_rpc_user: str | None = None,
            core_rpc_password: str | None = None,
            core_rpc_cookie: str | Path | None = None,
            core_rpc_timeout: float | None = None,
            api_host: str | None = None,
            api_port: int | None = None,
            api_allowed_origins: list[str] | tuple[str, ...] | None = None,
            api_tls_cert: str | Path | None = None,
            api_tls_key: str | Path | None = None,
    ) -> "BitCloneConfig":
        """Load persistent options from bitclone.toml, then apply explicit overrides."""
        if data_dir is not None:
            resolved_data_dir = Path(data_dir).expanduser()
        elif db_path is not None:
            resolved_data_dir = Path(db_path).expanduser().parent
        else:
            resolved_data_dir = DEFAULT_DATA_DIR

        config_path = resolved_data_dir / CONFIG_FILENAME
        values: dict[str, Any] = {}
        if config_path.exists():
            try:
                with config_path.open("rb") as stream:
                    values = tomllib.load(stream)
            except (OSError, tomllib.TOMLDecodeError) as error:
                raise ValueError(f"Cannot load {config_path}: {error}") from error
            if "core_rpc_password" in values:
                raise ValueError(
                    "core_rpc_password is not allowed in bitclone.toml; "
                    "use BITCLONE_CORE_RPC_PASSWORD"
                )
            if "api_token" in values:
                raise ValueError(
                    "api_token is not allowed in bitclone.toml; "
                    "use BITCLONE_API_TOKEN"
                )

        def configured(name: str, override: Any, default: Any = None) -> Any:
            return override if override is not None else values.get(name, default)

        return cls.from_options(
            data_dir=resolved_data_dir,
            network=configured("network", network, NetworkName.MAINNET),
            db_path=configured("db_path", db_path),
            upstream_host=configured("upstream_host", upstream_host),
            upstream_port=configured("upstream_port", upstream_port),
            block_storage=configured(
                "block_storage",
                block_storage,
                BlockStorageMode.ARCHIVAL,
            ),
            prune_keep_blocks=configured(
                "prune_keep_blocks",
                prune_keep_blocks,
                MIN_PRUNE_KEEP_BLOCKS,
            ),
            core_rpc_url=configured("core_rpc_url", core_rpc_url),
            core_rpc_user=configured("core_rpc_user", core_rpc_user),
            core_rpc_password=core_rpc_password,
            core_rpc_cookie=configured("core_rpc_cookie", core_rpc_cookie),
            core_rpc_timeout=configured("core_rpc_timeout", core_rpc_timeout, 10.0),
            api_host=configured("api_host", api_host, "127.0.0.1"),
            api_port=configured("api_port", api_port, 8334),
            api_allowed_origins=configured(
                "api_allowed_origins",
                api_allowed_origins,
                (),
            ),
            api_tls_cert=configured("api_tls_cert", api_tls_cert),
            api_tls_key=configured("api_tls_key", api_tls_key),
        )

    @property
    def config_path(self) -> Path:
        return self.data_dir / CONFIG_FILENAME

    @property
    def network_dir(self) -> Path:
        return self.data_dir / self.network.value

    @property
    def chainstate_dir(self) -> Path:
        return self.network_dir / "chainstate"

    @property
    def blocks_dir(self) -> Path:
        return self.network_dir / "blocks"

    @property
    def peers_dir(self) -> Path:
        return self.network_dir / "peers"

    @property
    def logs_dir(self) -> Path:
        return self.network_dir / "logs"

    @property
    def wallet_dir(self) -> Path:
        return self.network_dir / "wallet"

    @property
    def db_path(self) -> Path:
        return self.db_path_override or self.chainstate_dir / "bitclone.db"

    @property
    def magic_bytes(self) -> bytes:
        return self.profile.magic_bytes

    @property
    def p2p_port(self) -> int:
        return self.profile.p2p_port

    @property
    def configured_upstream_port(self) -> int:
        return self.upstream_port if self.upstream_port is not None else self.p2p_port

    @property
    def profile(self) -> NetworkProfile:
        return get_network_profile(self.network)

    def initialize(self) -> dict[str, str]:
        """
        Create the data-directory layout and a minimal config file if missing.
        """
        for directory in [
            self.data_dir,
            self.network_dir,
            self.chainstate_dir,
            self.blocks_dir,
            self.peers_dir,
            self.logs_dir,
            self.wallet_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)

        if not self.config_path.exists():
            self.config_path.write_text(self._default_config_text(), encoding="utf-8")

        return self.to_data()

    def to_data(self) -> dict[str, Any]:
        return {
            "data_dir": str(self.data_dir),
            "config_path": str(self.config_path),
            "network": self.network.value,
            "magic_bytes": self.magic_bytes.hex(),
            "p2p_port": self.p2p_port,
            "upstream_host": self.upstream_host,
            "upstream_port": self.configured_upstream_port if self.upstream_host is not None else None,
            "block_storage": self.block_storage.value,
            "prune_keep_blocks": self.prune_keep_blocks,
            "core_rpc_url": self.core_rpc_url,
            "core_rpc_user": self.core_rpc_user,
            "core_rpc_cookie": str(self.core_rpc_cookie) if self.core_rpc_cookie is not None else None,
            "core_rpc_timeout": self.core_rpc_timeout,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "api_allowed_origins": list(self.api_allowed_origins),
            "api_tls_cert": str(self.api_tls_cert) if self.api_tls_cert is not None else None,
            "api_tls_key": str(self.api_tls_key) if self.api_tls_key is not None else None,
            "network_dir": str(self.network_dir),
            "chainstate_dir": str(self.chainstate_dir),
            "blocks_dir": str(self.blocks_dir),
            "peers_dir": str(self.peers_dir),
            "logs_dir": str(self.logs_dir),
            "wallet_dir": str(self.wallet_dir),
            "db_path": str(self.db_path),
        }

    def _default_config_text(self) -> str:
        text = (
            "# BitClone configuration\n"
            f'data_dir = "{self.data_dir}"\n'
            f'network = "{self.network.value}"\n'
            f'block_storage = "{self.block_storage.value}"\n'
            f"prune_keep_blocks = {self.prune_keep_blocks}\n"
            f'api_host = "{self.api_host}"\n'
            f"api_port = {self.api_port}\n"
        )
        if self.api_allowed_origins:
            origins = ", ".join(f'"{origin}"' for origin in self.api_allowed_origins)
            text += f"api_allowed_origins = [{origins}]\n"
        if self.api_tls_cert is not None:
            text += f'api_tls_cert = "{self.api_tls_cert}"\n'
            text += f'api_tls_key = "{self.api_tls_key}"\n'
        text += "# Set BITCLONE_API_TOKEN in the environment; API tokens are not written here.\n"
        if self.core_rpc_url is not None:
            text += f'core_rpc_url = "{self.core_rpc_url}"\n'
        if self.core_rpc_user is not None:
            text += f'core_rpc_user = "{self.core_rpc_user}"\n'
        if self.core_rpc_cookie is not None:
            text += f'core_rpc_cookie = "{self.core_rpc_cookie}"\n'
        if self.core_rpc_url is not None:
            text += f"core_rpc_timeout = {self.core_rpc_timeout}\n"
        if self.block_storage is BlockStorageMode.BITCOIN_CORE_REMOTE:
            text += "# Set BITCLONE_CORE_RPC_PASSWORD in the environment; passwords are not written here.\n"
        if self.upstream_host is not None:
            text += f'upstream_host = "{self.upstream_host}"\n'
            text += f"upstream_port = {self.configured_upstream_port}\n"
        else:
            text += "# upstream_host and upstream_port may select a preferred Bitcoin Core peer.\n"
        return text
