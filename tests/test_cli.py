import json

from src.cli import main
from src.node.node import Node
from src.tx.tx import Tx, TxIn, TxOut, UTXO


def _coinbase_tx() -> Tx:
    return Tx(
        inputs=[TxIn(b"\x00" * 32, 0xffffffff, b"\x01\x01", 0xffffffff)],
        outputs=[TxOut(1, b"\x51")],
    )


def test_status_outputs_json(tmp_path, capsys):
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "--json", "status"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["height"] == 0
    assert output["mempool_size"] == 0
    assert output["started"] is False
    assert output["network"] == "mainnet"


def test_status_outputs_plain_text(tmp_path, capsys):
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "status"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "height: 0" in output
    assert "mempool_size: 0" in output


def test_init_creates_data_directory_layout(tmp_path, capsys):
    exit_code = main(["--data-dir", str(tmp_path), "--network", "regtest", "--json", "init"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["network"] == "regtest"
    assert output["db_path"] == str(tmp_path / "regtest" / "chainstate" / "bitclone.db")
    assert (tmp_path / "bitclone.toml").exists()
    assert (tmp_path / "regtest" / "chainstate").is_dir()
    assert (tmp_path / "regtest" / "blocks").is_dir()
    assert (tmp_path / "regtest" / "peers").is_dir()
    assert (tmp_path / "regtest" / "logs").is_dir()
    assert (tmp_path / "regtest" / "wallet").is_dir()


def test_status_uses_data_dir_and_network_without_db_path(tmp_path, capsys):
    exit_code = main(["--data-dir", str(tmp_path), "--network", "regtest", "--json", "status"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["network"] == "regtest"
    assert output["db_path"] == str(tmp_path / "regtest" / "chainstate" / "bitclone.db")
    assert (tmp_path / "regtest" / "chainstate" / "bitclone.db").exists()
    assert (tmp_path / "regtest" / "blocks").is_dir()


def test_build_template_outputs_candidate_block(tmp_path, capsys):
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "--json", "build-template"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["tx_num"] == 1
    assert output["txs"]["0"]["is_coinbase"] is True


def test_gettxout_finds_genesis_utxo(tmp_path, capsys):
    db_path = tmp_path / "node.db"
    node = Node(db_path=db_path)
    try:
        genesis_tx = node.blockchain.tip.txs[0]
        txid = genesis_tx.txid[::-1].hex()
    finally:
        node.close()

    exit_code = main(["--db-path", str(db_path), "--json", "gettxout", txid, "0"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["found"] is True
    assert output["utxo"]["amount"] == 5_000_000_000
    assert output["utxo"]["is_coinbase"] is True


def test_getblock_finds_genesis_block(tmp_path, capsys):
    db_path = tmp_path / "node.db"
    node = Node(db_path=db_path)
    try:
        block_hash = node.blockchain.tip.block_id[::-1].hex()
    finally:
        node.close()

    exit_code = main(["--db-path", str(db_path), "--json", "getblock", block_hash])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["found"] is True
    assert output["block"]["tx_num"] == 1


def test_getchaintip_outputs_active_tip(tmp_path, capsys):
    db_path = tmp_path / "node.db"
    node = Node(db_path=db_path)
    try:
        block_hash = node.blockchain.tip.block_id[::-1].hex()
    finally:
        node.close()

    exit_code = main(["--db-path", str(db_path), "--json", "getchaintip"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["found"] is True
    assert output["tip"]["height"] == 0
    assert output["tip"]["block_hash"] == block_hash
    assert output["tip"]["active"] is True


def test_getchaintip_outputs_plain_text(tmp_path, capsys):
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "getchaintip"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "found: True" in output
    assert "height" in output


def test_getblockheader_finds_genesis_header(tmp_path, capsys):
    db_path = tmp_path / "node.db"
    node = Node(db_path=db_path)
    try:
        block_hash = node.blockchain.tip.block_id[::-1].hex()
    finally:
        node.close()

    exit_code = main(["--db-path", str(db_path), "--json", "getblockheader", block_hash])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["found"] is True
    assert output["height"] == 0
    assert output["header"]["block_hash"] == block_hash
    assert output["header"]["bits"] == "1d00ffff"
    assert output["index"]["height"] == 0
    assert output["index"]["active"] is True


def test_getblockheader_returns_not_found_for_unknown_hash(tmp_path, capsys):
    unknown_hash = "11" * 32

    exit_code = main(["--db-path", str(tmp_path / "node.db"), "--json", "getblockheader", unknown_hash])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "found": False,
        "block_hash": unknown_hash,
    }


def test_sendrawtransaction_prints_txid_for_rejected_tx(tmp_path, capsys):
    tx = _coinbase_tx()
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "--json", "sendrawtransaction", tx.to_bytes().hex()])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "accepted": False,
        "txid": tx.txid[::-1].hex(),
    }


def test_sendrawtransaction_accepts_valid_tx_when_utxo_exists(tmp_path, capsys):
    db_path = tmp_path / "node.db"
    seed_node = Node(db_path=db_path)
    try:
        funding_txid = b"\x11" * 32
        utxo = UTXO(
            outpoint=funding_txid + (0).to_bytes(4, "little"),
            amount=100_000,
            scriptpubkey=b"\x51",
            block_height=1,
        )
        seed_node.blockchain.db.add_utxo(utxo)
    finally:
        seed_node.close()

    tx = Tx(
        inputs=[TxIn(funding_txid, 0, b"", 0xffffffff)],
        outputs=[TxOut(90_000, b"\x51")],
    )

    exit_code = main(["--db-path", str(db_path), "--json", "sendrawtransaction", tx.to_bytes().hex()])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["accepted"] is True
    assert output["txid"] == tx.txid[::-1].hex()
