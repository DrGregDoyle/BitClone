"""
Command-line interface for BitClone.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from src.config import BitCloneConfig, BlockStorageMode, NetworkName
from src.core import ReadError, TransactionError
from src.node.node import Node
from src.tx.tx import Tx


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bitclone",
        description="BitClone node command-line interface",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Override the chainstate sqlite database path.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="BitClone data directory. Defaults to ~/.bitclone.",
    )
    parser.add_argument(
        "--network",
        choices=[n.value for n in NetworkName],
        default=NetworkName.MAINNET.value,
        help="Network data namespace.",
    )
    parser.add_argument(
        "--upstream-host",
        default=None,
        help="Preferred Bitcoin Core P2P host for synchronization.",
    )
    parser.add_argument(
        "--upstream-port",
        type=int,
        default=None,
        help="Preferred upstream P2P port; defaults to the selected network port.",
    )
    parser.add_argument(
        "--block-storage",
        choices=[mode.value for mode in BlockStorageMode],
        default=BlockStorageMode.ARCHIVAL.value,
        help="Retain all blocks or keep only a recent pruned window.",
    )
    parser.add_argument(
        "--prune-keep-blocks",
        type=int,
        default=288,
        help="Recent block bodies and undo records retained in pruned mode.",
    )
    parser.add_argument(
        "--core-rpc-url",
        default=None,
        help="Bitcoin Core JSON-RPC URL used by bitcoin-core-remote storage.",
    )
    parser.add_argument("--core-rpc-user", default=None, help="Bitcoin Core RPC username.")
    parser.add_argument(
        "--core-rpc-cookie",
        type=Path,
        default=None,
        help="Local path to a Bitcoin Core RPC cookie file.",
    )
    parser.add_argument(
        "--core-rpc-timeout",
        type=float,
        default=10.0,
        help="Bitcoin Core RPC timeout in seconds.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print command output as JSON.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create the BitClone data-directory layout.")
    subparsers.add_parser("status", help="Show node status.")
    subparsers.add_parser("build-template", help="Build and print a candidate block template.")
    subparsers.add_parser("getchaintip", help="Show the active chain tip.")
    subparsers.add_parser(
        "getremotechaininfo",
        help="Query the configured Bitcoin Core remote block source.",
    )

    getblockheader = subparsers.add_parser("getblockheader", help="Read a block header by display hash.")
    getblockheader.add_argument("block_hash", help="Block hash in display byte order.")

    sendraw = subparsers.add_parser("sendrawtransaction", help="Submit a raw transaction hex string to the mempool.")
    sendraw.add_argument("tx_hex", help="Serialized transaction hex.")

    decoderaw = subparsers.add_parser("decoderawtransaction", help="Decode a raw transaction hex string.")
    decoderaw.add_argument("tx_hex", help="Serialized transaction hex.")

    getrawmempool = subparsers.add_parser("getrawmempool", help="List mempool transaction ids.")
    getrawmempool.add_argument(
        "--verbose",
        action="store_true",
        help="Include fee, size, and ancestor/descendant metadata.",
    )

    getblock = subparsers.add_parser("getblock", help="Read a block by display hash.")
    getblock.add_argument("block_hash", help="Block hash in display byte order.")

    gettxout = subparsers.add_parser("gettxout", help="Read a UTXO by display txid and output index.")
    gettxout.add_argument("txid", help="Transaction id in display byte order.")
    gettxout.add_argument("vout", type=int, help="Output index.")

    return parser


def _print_output(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return

    if isinstance(data, dict):
        for key, value in data.items():
            print(f"{key}: {value}")
        return

    print(data)


def _decode_hex(value: str, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"{name} must be valid hex") from e


def _decode_display_hash(value: str, name: str) -> bytes:
    raw = _decode_hex(value, name)
    if len(raw) != 32:
        raise argparse.ArgumentTypeError(f"{name} must be 32 bytes / 64 hex characters")
    return raw[::-1]


def _format_block_index(entry) -> dict[str, Any] | None:
    if entry is None:
        return None

    return {
        "block_hash": entry.block_hash[::-1].hex(),
        "prev_hash": entry.prev_hash[::-1].hex(),
        "height": entry.height,
        "bits": entry.bits.hex(),
        "timestamp": entry.timestamp,
        "work": entry.work,
        "chainwork": entry.chainwork,
        "active": entry.active,
        "status": entry.status,
    }


def _format_block_header(node: Node, block_hash: bytes, display_hash: str) -> dict[str, Any]:
    index_entry = node.blockchain.get_block_index(block_hash)
    block = node.blockchain.get_block(block_hash) if index_entry is not None else None
    header = block.get_header() if block is not None else node.blockchain.get_remote_block_header(block_hash)

    if header is None:
        return {"found": False, "block_hash": display_hash}

    return {
        "found": True,
        "height": index_entry.height if index_entry is not None else None,
        "header": header.to_data(),
        "index": _format_block_index(index_entry),
    }


def _decode_tx(tx_hex: str) -> Tx:
    try:
        return Tx.from_bytes(_decode_hex(tx_hex, "tx_hex"))
    except (ReadError, TransactionError, ValueError) as e:
        raise argparse.ArgumentTypeError(f"tx_hex is not a valid serialized transaction: {e}") from e


def _handle_command(node: Node, args: argparse.Namespace) -> Any:
    match args.command:
        case "status":
            return node.status()
        case "build-template":
            return node.build_block_template().to_data()
        case "getchaintip":
            tip = node.blockchain.db.get_active_tip()
            return {"found": tip is not None, "tip": _format_block_index(tip)}
        case "getremotechaininfo":
            info = node.remote_blockchain_info()
            return {"configured": info is not None, "blockchain": info}
        case "getblockheader":
            block_hash = _decode_display_hash(args.block_hash, "block_hash")
            return _format_block_header(node, block_hash, args.block_hash)
        case "sendrawtransaction":
            tx = _decode_tx(args.tx_hex)
            accepted = node.submit_tx(tx)
            return {
                "accepted": accepted,
                "txid": tx.txid[::-1].hex(),
            }
        case "decoderawtransaction":
            tx = _decode_tx(args.tx_hex)
            return tx.to_data()
        case "getrawmempool":
            return node.mempool.to_data(verbose=args.verbose)
        case "getblock":
            block_hash = _decode_display_hash(args.block_hash, "block_hash")
            block = node.blockchain.get_block(block_hash)
            if block is None:
                return {"found": False, "block_hash": args.block_hash}
            return {"found": True, "block": block.to_data()}
        case "gettxout":
            txid = _decode_display_hash(args.txid, "txid")
            outpoint = txid + args.vout.to_bytes(4, "little")
            utxo = node.blockchain.get_utxo(outpoint)
            if utxo is None:
                return {"found": False, "txid": args.txid, "vout": args.vout}
            return {"found": True, "utxo": utxo.to_data()}
        case _:
            raise ValueError(f"Unsupported command: {args.command}")


def _config_from_args(args: argparse.Namespace) -> BitCloneConfig:
    return BitCloneConfig.from_options(
        data_dir=args.data_dir,
        network=args.network,
        db_path=args.db_path,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        block_storage=args.block_storage,
        prune_keep_blocks=args.prune_keep_blocks,
        core_rpc_url=args.core_rpc_url,
        core_rpc_user=args.core_rpc_user,
        core_rpc_password=os.environ.get("BITCLONE_CORE_RPC_PASSWORD"),
        core_rpc_cookie=args.core_rpc_cookie,
        core_rpc_timeout=args.core_rpc_timeout,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = _config_from_args(args)

    if args.command == "init":
        _print_output(config.initialize(), args.json)
        return 0

    node = Node(config=config)
    try:
        output = _handle_command(node, args)
        _print_output(output, args.json)
        return 0
    except (ValueError, argparse.ArgumentTypeError) as e:
        parser.exit(2, f"{parser.prog}: error: {e}\n")
    finally:
        node.close()


if __name__ == "__main__":
    sys.exit(main())
