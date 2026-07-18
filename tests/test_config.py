from src.config import BitCloneConfig, NetworkName
from src.core import MAGICBYTES, NETWORK


def test_config_builds_network_scoped_paths(tmp_path):
    config = BitCloneConfig.from_options(data_dir=tmp_path, network="regtest")

    assert config.data_dir == tmp_path
    assert config.network == NetworkName.REGTEST
    assert config.network_dir == tmp_path / "regtest"
    assert config.chainstate_dir == tmp_path / "regtest" / "chainstate"
    assert config.blocks_dir == tmp_path / "regtest" / "blocks"
    assert config.peers_dir == tmp_path / "regtest" / "peers"
    assert config.logs_dir == tmp_path / "regtest" / "logs"
    assert config.wallet_dir == tmp_path / "regtest" / "wallet"
    assert config.db_path == tmp_path / "regtest" / "chainstate" / "bitclone.db"
    assert config.magic_bytes == MAGICBYTES.REGTEST
    assert config.p2p_port == NETWORK.REGTEST_PORT


def test_config_db_path_override_keeps_network_layout(tmp_path):
    db_path = tmp_path / "custom.db"
    config = BitCloneConfig.from_options(data_dir=tmp_path / "data", network="testnet", db_path=db_path)

    assert config.network == NetworkName.TESTNET
    assert config.magic_bytes == MAGICBYTES.TESTNET
    assert config.db_path == db_path
    assert config.blocks_dir == tmp_path / "data" / "testnet" / "blocks"


def test_config_supports_signet(tmp_path):
    config = BitCloneConfig.from_options(data_dir=tmp_path, network="signet")

    assert config.network == NetworkName.SIGNET
    assert config.magic_bytes == MAGICBYTES.SIGNET
    assert config.p2p_port == NETWORK.SIGNET_PORT
    assert config.network_dir == tmp_path / "signet"


def test_config_uses_network_specific_p2p_ports(tmp_path):
    expected_ports = {
        "mainnet": NETWORK.MAINNET_PORT,
        "testnet": NETWORK.TESTNET_PORT,
        "regtest": NETWORK.REGTEST_PORT,
        "signet": NETWORK.SIGNET_PORT,
    }

    for network, expected_port in expected_ports.items():
        config = BitCloneConfig.from_options(data_dir=tmp_path, network=network)

        assert config.p2p_port == expected_port
        assert config.to_data()["p2p_port"] == expected_port


def test_initialize_creates_data_directory_layout(tmp_path):
    config = BitCloneConfig.from_options(data_dir=tmp_path, network="regtest")

    result = config.initialize()

    assert config.config_path.exists()
    assert config.chainstate_dir.is_dir()
    assert config.blocks_dir.is_dir()
    assert config.peers_dir.is_dir()
    assert config.logs_dir.is_dir()
    assert config.wallet_dir.is_dir()
    assert result["network"] == "regtest"
    assert result["db_path"] == str(config.db_path)
