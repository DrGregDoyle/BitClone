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


def test_status_outputs_plain_text(tmp_path, capsys):
    exit_code = main(["--db-path", str(tmp_path / "node.db"), "status"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "height: 0" in output
    assert "mempool_size: 0" in output


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
