"""
Configuration and data-directory paths for BitClone.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.core.network_profiles import NetworkName, NetworkProfile, get_network_profile


DEFAULT_DATA_DIR = Path.home() / ".bitclone"
CONFIG_FILENAME = "bitclone.toml"


@dataclass(frozen=True, slots=True)
class BitCloneConfig:
    data_dir: Path = DEFAULT_DATA_DIR
    network: NetworkName = NetworkName.MAINNET
    db_path_override: Path | None = None

    @classmethod
    def from_options(
            cls,
            data_dir: str | Path | None = None,
            network: str | NetworkName = NetworkName.MAINNET,
            db_path: str | Path | None = None,
    ) -> "BitCloneConfig":
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
            "network_dir": str(self.network_dir),
            "chainstate_dir": str(self.chainstate_dir),
            "blocks_dir": str(self.blocks_dir),
            "peers_dir": str(self.peers_dir),
            "logs_dir": str(self.logs_dir),
            "wallet_dir": str(self.wallet_dir),
            "db_path": str(self.db_path),
        }

    def _default_config_text(self) -> str:
        return (
            "# BitClone configuration\n"
            f'data_dir = "{self.data_dir}"\n'
            f'network = "{self.network.value}"\n'
        )
