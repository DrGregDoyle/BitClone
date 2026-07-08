"""
Command-line interface for BitClone.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from src.block.block import Block
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
        help="Path to the chainstate sqlite database.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print command output as JSON.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show node status.")
    subparsers.add_parser("build-template", help="Build and print a candidate block template.")

    sendraw = subparsers.add_parser("sendrawtransaction", help="Submit a raw transaction hex string to the mempool.")
    sendraw.add_argument("tx_hex", help="Serialized transaction hex.")

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


def _handle_command(node: Node, args: argparse.Namespace) -> Any:
    match args.command:
        case "status":
            return node.status()
        case "build-template":
            return node.build_block_template().to_data()
        case "sendrawtransaction":
            tx = Tx.from_bytes(_decode_hex(args.tx_hex, "tx_hex"))
            accepted = node.submit_tx(tx)
            return {
                "accepted": accepted,
                "txid": tx.txid[::-1].hex(),
            }
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    node = Node(db_path=args.db_path)
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
