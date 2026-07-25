from pathlib import Path

import pytest

from src.blockchain.blockchain import Blockchain, WITNESS_SCALE_FACTOR
from src.core import NetworkName, ScriptVerifyFlag
from src.cryptography import sha256
from src.script import BitNum, P2SH_Key, ScriptEngine, ScriptValidationInput, SignatureVersion
from src.script.stack_ops import encode_pushdata
from src.tx.tx import LoadedTx, Tx, TxIn, TxOut, UTXO, Witness
from src.tx.validation import validate_tx_scripts


def _spend(
        utxo: UTXO,
        *,
        scriptsig: bytes = b"",
        witness_items: list[bytes] | None = None,
) -> Tx:
    return Tx(
        inputs=[
            TxIn(
                utxo.outpoint[:32],
                utxo.outpoint[32:],
                scriptsig,
                0xffffffff,
            )
        ],
        outputs=[TxOut(1, b"\x51")],
        witness=[Witness(witness_items)] if witness_items is not None else None,
    )


@pytest.fixture()
def chain(tmp_path: Path):
    blockchain = Blockchain(
        db_path=tmp_path / "chain.db",
        network=NetworkName.REGTEST,
    )
    yield blockchain
    blockchain.close()


def test_script_validation_input_requires_every_spent_output():
    tx = Tx(
        inputs=[TxIn(b"\x11" * 32, 0, b"", 0xffffffff)],
        outputs=[TxOut(1, b"\x51")],
    )

    with pytest.raises(ValueError, match="one spent output"):
        ScriptValidationInput(
            tx=tx,
            input_index=0,
            spent_outputs=(),
            flags=ScriptVerifyFlag.P2SH,
        )


def test_script_validation_input_builds_explicit_execution_mode():
    outpoint = b"\x22" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, b"\x51", 0)
    tx = _spend(utxo)
    validation = ScriptValidationInput(
        tx=tx,
        input_index=0,
        spent_outputs=(utxo,),
        flags=ScriptVerifyFlag.WITNESS,
    )

    context = validation.execution_context(
        signature_version=SignatureVersion.WITNESS_V0,
    )

    assert context.tx is tx
    assert context.utxo is utxo
    assert context.is_segwit
    assert not context.tapscript


def test_nested_p2wsh_executes_witness_script():
    witness_script = b"\x51"  # OP_1
    witness_program = b"\x00\x20" + sha256(witness_script)
    scriptpubkey = P2SH_Key.from_data(witness_program).script
    outpoint = b"\x33" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, scriptpubkey, 0)
    tx = _spend(
        utxo,
        scriptsig=encode_pushdata(witness_program),
        witness_items=[witness_script],
    )

    assert validate_tx_scripts(
        LoadedTx(tx, [utxo]),
        flags=ScriptVerifyFlag.P2SH | ScriptVerifyFlag.WITNESS,
    )


def test_nested_witness_rejects_extra_scriptsig_stack_item():
    witness_script = b"\x51"
    witness_program = b"\x00\x20" + sha256(witness_script)
    scriptpubkey = P2SH_Key.from_data(witness_program).script
    outpoint = b"\x44" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, scriptpubkey, 0)
    tx = _spend(
        utxo,
        scriptsig=b"\x51" + encode_pushdata(witness_program),
        witness_items=[witness_script],
    )

    assert not validate_tx_scripts(
        LoadedTx(tx, [utxo]),
        flags=ScriptVerifyFlag.P2SH | ScriptVerifyFlag.WITNESS,
    )


def test_p2sh_redeem_script_sigops_are_accurate_and_scaled(chain):
    redeem_script = b"\x52\xae"  # OP_2 OP_CHECKMULTISIG
    scriptpubkey = P2SH_Key.from_data(redeem_script).script
    outpoint = b"\x55" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, scriptpubkey, 0)
    tx = _spend(utxo, scriptsig=encode_pushdata(redeem_script))

    assert chain._tx_sigop_cost(tx, [utxo]) == 2 * WITNESS_SCALE_FACTOR


def test_p2wsh_sigops_use_unscaled_witness_cost(chain):
    witness_script = b"\x52\xae"  # OP_2 OP_CHECKMULTISIG
    scriptpubkey = b"\x00\x20" + sha256(witness_script)
    outpoint = b"\x66" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, scriptpubkey, 0)
    tx = _spend(utxo, witness_items=[b"", witness_script])

    assert chain._tx_sigop_cost(tx, [utxo]) == 2


def test_tapscript_uses_validation_budget_not_legacy_block_sigop_cost(chain):
    tapscript = b"\xac\xba"  # OP_CHECKSIG OP_CHECKSIGADD
    scriptpubkey = b"\x51\x20" + b"\x77" * 32
    outpoint = b"\x77" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, scriptpubkey, 0)
    tx = _spend(
        utxo,
        witness_items=[b"argument", tapscript, b"\xc0" + b"\x88" * 32],
    )

    assert chain._tx_sigop_cost(tx, [utxo]) == 0
    assert chain._count_sigops(tapscript, tapscript=True) == 2
    assert chain._count_sigops(b"\xba") == 0


def test_checksigadd_empty_signature_preserves_count_and_budget():
    outpoint = b"\x99" * 32 + (0).to_bytes(4, "little")
    utxo = UTXO(outpoint, 2, b"\x51\x20" + b"\xaa" * 32, 0)
    tx = _spend(utxo)
    context = ScriptValidationInput(
        tx=tx,
        input_index=0,
        spent_outputs=(utxo,),
        flags=ScriptVerifyFlag.TAPROOT,
    ).execution_context(
        signature_version=SignatureVersion.TAPSCRIPT,
        tapleaf_hash=b"\xbb" * 32,
    )
    engine = ScriptEngine()
    engine.stack.push(b"")
    engine.stack.push(BitNum(2).to_bytes())
    engine.stack.push(b"\xcc" * 32)
    engine.tapscript_validation_weight_left = 50

    assert engine.execute_script(b"\xba", context)
    assert engine.stack.popnum() == 2
    assert engine.tapscript_validation_weight_left == 50
    assert engine._consume_tapscript_sigop(b"non-empty")
    assert not engine._consume_tapscript_sigop(b"non-empty")
