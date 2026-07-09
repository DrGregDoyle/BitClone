from src.config import BitCloneConfig, NetworkName


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


def test_config_db_path_override_keeps_network_layout(tmp_path):
    db_path = tmp_path / "custom.db"
    config = BitCloneConfig.from_options(data_dir=tmp_path / "data", network="testnet", db_path=db_path)

    assert config.network == NetworkName.TESTNET
    assert config.db_path == db_path
    assert config.blocks_dir == tmp_path / "data" / "testnet" / "blocks"


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
