"""
Shared transaction validation helpers.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from src.core import get_logger
from src.script import classify_scriptpubkey, ExecutionContext, P2WSH_Key, P2WPKH_Key, P2TR_Key, ScriptEngine, \
    ScriptType, classify_scriptsig
from src.tx.tx import LoadedTx, UTXO

logger = get_logger(__name__)

MAX_MONEY = 21_000_000 * 100_000_000
MAX_TX_WEIGHT = 4_000_000


@dataclass(slots=True)
class TxValidationContext:
    """
    Context for checks that depend on where a transaction is being validated.
    """
    next_height: int | None = None
    block_timestamp: int | None = None
    seen_outpoints: set[bytes] | None = None
    get_block_at_height: Callable[[int], object | None] | None = None
    coinbase_maturity: int | None = None
    check_locktime: bool = False
    check_relative_locktime: bool = False
    validate_scripts: bool = True
    script_validator: Callable[[LoadedTx], bool] | None = None
    current_time: int = field(default_factory=lambda: int(time.time()))


def validate_loaded_tx(loaded_tx: LoadedTx, ctx: TxValidationContext | None = None) -> bool:
    """
    Validate a non-coinbase transaction whose referenced UTXOs are already loaded.
    """
    ctx = ctx or TxValidationContext()
    tx = loaded_tx.tx

    if not _validate_tx_structure(loaded_tx):
        return False

    if tx.is_coinbase:
        logger.error("Coinbase transaction cannot be validated as a regular spend")
        return False

    try:
        _ = loaded_tx.fee
    except Exception as e:
        logger.error(f"Fee validation failed for tx {tx.txid.hex()}: {e}")
        return False

    if ctx.check_locktime and not _validate_absolute_locktime(loaded_tx, ctx):
        return False

    local_seen: set[bytes] = set()
    seen_outpoints = ctx.seen_outpoints

    for i, txin in enumerate(tx.inputs):
        utxo = loaded_tx.utxo_for_input(i)

        if txin.outpoint in local_seen:
            logger.error(f"Duplicate input within tx: {txin.outpoint.hex()}")
            return False
        local_seen.add(txin.outpoint)

        if seen_outpoints is not None:
            if txin.outpoint in seen_outpoints:
                logger.error(f"Double spend within block: {txin.outpoint.hex()}")
                return False
            seen_outpoints.add(txin.outpoint)

        if ctx.coinbase_maturity is not None and ctx.next_height is not None:
            if utxo.is_coinbase and (ctx.next_height - utxo.block_height) < ctx.coinbase_maturity:
                logger.error(f"Coinbase UTXO spent before maturity: {txin.outpoint.hex()}")
                return False

        if ctx.check_relative_locktime and not _validate_relative_locktime(txin.sequence, utxo, ctx, txin.outpoint):
            return False

    script_validator = ctx.script_validator or validate_tx_scripts
    if ctx.validate_scripts and not script_validator(loaded_tx):
        logger.error(f"Script validation failed for tx: {tx.txid.hex()}")
        return False

    return True


def _validate_tx_structure(loaded_tx: LoadedTx) -> bool:
    tx = loaded_tx.tx

    if not tx.inputs:
        logger.error("Regular transaction must have at least one input")
        return False

    if not tx.outputs:
        logger.error("Transaction must have at least one output")
        return False

    for output in tx.outputs:
        if output.amount < 0:
            logger.error("Transaction output has a negative amount")
            return False
        if output.amount > MAX_MONEY:
            logger.error(f"Transaction output amount exceeds max money: {output.amount}")
            return False

    output_total = loaded_tx.output_total
    if output_total > MAX_MONEY:
        logger.error(f"Transaction output total exceeds max money: {output_total}")
        return False

    for utxo in loaded_tx.utxos:
        if utxo.amount < 0:
            logger.error(f"Referenced UTXO has a negative amount: {utxo.outpoint.hex()}")
            return False
        if utxo.amount > MAX_MONEY:
            logger.error(f"Referenced UTXO amount exceeds max money: {utxo.outpoint.hex()}")
            return False

    if tx.is_segwit and len(tx.witness) != len(tx.inputs):
        logger.error("SegWit transaction must have one witness field per input")
        return False

    try:
        tx_weight = tx.wu
    except Exception as e:
        logger.error(f"Transaction weight calculation failed: {e}")
        return False

    if tx_weight > MAX_TX_WEIGHT:
        logger.error(f"Transaction weight {tx_weight} WU exceeds max {MAX_TX_WEIGHT} WU")
        return False

    return True


def validate_tx_scripts(loaded_tx: LoadedTx) -> bool:
    """
    Validate all input scripts for a loaded transaction.
    """
    tx = loaded_tx.tx
    utxos = loaded_tx.utxos

    for i, txin in enumerate(tx.inputs):
        spent_utxo = loaded_tx.utxo_for_input(i)
        scriptpubkey = classify_scriptpubkey(spent_utxo.scriptpubkey)
        scriptsig = None

        input_is_native_segwit = type(scriptpubkey) in [P2WPKH_Key, P2WSH_Key, P2TR_Key]
        input_is_nested_segwit = False
        if not input_is_native_segwit:
            scriptsig = classify_scriptsig(txin.scriptsig)
            input_is_nested_segwit = scriptsig.script_type == ScriptType.P2SH_P2WPKH

        exec_ctx = ExecutionContext(
            tx=tx,
            input_index=i,
            utxos=utxos,
            script_code=None,
            is_segwit=input_is_native_segwit or input_is_nested_segwit,
            tapscript=False,
            merkle_root=None,
        )

        script_engine = ScriptEngine()
        if input_is_native_segwit:
            ok = script_engine.validate_segwit(scriptpubkey, exec_ctx)
        else:
            ok = script_engine.validate_script_pair(scriptpubkey, scriptsig, exec_ctx)

        if not ok:
            return False

    return True


def _validate_absolute_locktime(loaded_tx: LoadedTx, ctx: TxValidationContext) -> bool:
    tx = loaded_tx.tx
    if tx.locktime == 0 or all(txin.sequence == 0xffffffff for txin in tx.inputs):
        return True

    if tx.locktime < 500_000_000:
        if ctx.next_height is not None and tx.locktime >= ctx.next_height:
            logger.error(f"Tx {tx.txid.hex()} absolute block-height locktime not yet reached")
            return False
    elif tx.locktime > ctx.current_time:
        logger.error(f"Tx {tx.txid.hex()} absolute time-based locktime not yet reached")
        return False

    return True


def _validate_relative_locktime(sequence: int, utxo: UTXO, ctx: TxValidationContext, outpoint: bytes) -> bool:
    if sequence & (1 << 31):
        return True

    if sequence & (1 << 22):
        if ctx.block_timestamp is None or ctx.get_block_at_height is None:
            return True

        required_seconds = (sequence & 0xFFFF) * 512
        utxo_block = ctx.get_block_at_height(utxo.block_height)
        if utxo_block is not None and ctx.block_timestamp - utxo_block.timestamp < required_seconds:
            logger.error(f"Relative time-based locktime not met for input {outpoint.hex()}")
            return False
    else:
        if ctx.next_height is None:
            return True

        required_blocks = sequence & 0xFFFF
        if (ctx.next_height - utxo.block_height) < required_blocks:
            logger.error(f"Relative block-based locktime not met for input {outpoint.hex()}")
            return False

    return True
