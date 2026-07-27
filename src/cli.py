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

from src.api import BitCloneHTTPServer, NodeApplicationService
from src.api.security import generate_api_token
from src.api.service import RPCError
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
        default=None,
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
        default=None,
        help="Retain all blocks or keep only a recent pruned window.",
    )
    parser.add_argument(
        "--prune-keep-blocks",
        type=int,
        default=None,
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
        default=None,
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
    subparsers.add_parser("getblockchaininfo", help="Show Bitcoin-compatible chain status.")
    subparsers.add_parser("getnetworkinfo", help="Show Bitcoin-compatible network status.")
    subparsers.add_parser("getpeerinfo", help="Show connected peers in Bitcoin RPC format.")
    serve_api = subparsers.add_parser(
        "serve-api",
        help="Run the local versioned REST API until interrupted.",
    )
    serve_api.add_argument(
        "--port",
        type=int,
        default=None,
        help="API port. Defaults to the configured port or 8334.",
    )
    serve_api.add_argument(
        "--host",
        default=None,
        help="API bind host. Non-loopback addresses require TLS and an allowed origin.",
    )
    serve_api.add_argument(
        "--allowed-origin",
        action="append",
        default=None,
        help="Allowed browser origin. Repeat for multiple origins.",
    )
    serve_api.add_argument(
        "--tls-cert",
        type=Path,
        default=None,
        help="PEM TLS certificate for API serving.",
    )
    serve_api.add_argument(
        "--tls-key",
        type=Path,
        default=None,
        help="PEM private key for the API certificate.",
    )
    serve_api.add_argument(
        "--api-only",
        action="store_true",
        help="Serve the API without starting BitClone's public P2P workers.",
    )
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

    getrawtransaction = subparsers.add_parser(
        "getrawtransaction",
        help="Read a mempool transaction or a confirmed transaction with its block hash.",
    )
    getrawtransaction.add_argument("txid", help="Transaction id in display byte order.")
    getrawtransaction.add_argument("--verbose", action="store_true")
    getrawtransaction.add_argument("--block-hash", default=None)

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


def _decode_tx(tx_hex: str) -> Tx:
    try:
        return Tx.from_bytes(_decode_hex(tx_hex, "tx_hex"))
    except (ReadError, TransactionError, ValueError) as e:
        raise argparse.ArgumentTypeError(f"tx_hex is not a valid serialized transaction: {e}") from e


def _handle_command(node: Node, args: argparse.Namespace) -> Any:
    service = NodeApplicationService(node)
    match args.command:
        case "status":
            return service.command_status()
        case "build-template":
            return node.build_block_template().to_data()
        case "getchaintip":
            return service.command_chain_tip()
        case "getremotechaininfo":
            return service.command_remote_chain_info()
        case "getblockchaininfo" | "getnetworkinfo" | "getpeerinfo":
            return service.dispatch_rpc(args.command)
        case "getblockheader":
            return service.command_block_header(args.block_hash)
        case "sendrawtransaction":
            tx = _decode_tx(args.tx_hex)
            try:
                txid = service.dispatch_rpc("sendrawtransaction", [args.tx_hex])
                accepted = True
            except RPCError as error:
                if error.code != -26:
                    raise
                txid = tx.txid[::-1].hex()
                accepted = False
            return {
                "accepted": accepted,
                "txid": txid,
            }
        case "decoderawtransaction":
            return service.dispatch_rpc("decoderawtransaction", [args.tx_hex])
        case "getrawmempool":
            return service.dispatch_rpc("getrawmempool", [args.verbose])
        case "getrawtransaction":
            return service.dispatch_rpc(
                "getrawtransaction",
                [args.txid, args.verbose, args.block_hash],
            )
        case "getblock":
            return service.command_block(args.block_hash)
        case "gettxout":
            result = service.dispatch_rpc("gettxout", [args.txid, args.vout, True])
            if result is None:
                return {"found": False, "txid": args.txid, "vout": args.vout}
            return {
                "found": True,
                "utxo": {
                    "outpoint": result["outpoint"],
                    "txid": args.txid,
                    "vout": args.vout,
                    "amount": result["amount_sats"],
                    "scriptpubkey": result["scriptPubKey"]["hex"],
                    "block_height": result["block_height"],
                    "is_coinbase": result["coinbase"],
                },
            }
        case _:
            raise ValueError(f"Unsupported command: {args.command}")


def _config_from_args(args: argparse.Namespace) -> BitCloneConfig:
    return BitCloneConfig.from_toml(
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
        api_host=getattr(args, "host", None),
        api_port=getattr(args, "port", None),
        api_allowed_origins=getattr(args, "allowed_origin", None),
        api_tls_cert=getattr(args, "tls_cert", None),
        api_tls_key=getattr(args, "tls_key", None),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        config = _config_from_args(args)
    except ValueError as error:
        parser.exit(2, f"{parser.prog}: error: {error}\n")

    if args.command == "init":
        _print_output(config.initialize(), args.json)
        return 0

    node = None
    try:
        node = Node(config=config)
        if args.command == "serve-api":
            if not args.api_only:
                node.start()
            configured_token = os.environ.get("BITCLONE_API_TOKEN")
            api_token = configured_token or generate_api_token()
            server = BitCloneHTTPServer(
                NodeApplicationService(node),
                api_token=api_token,
                host=config.api_host,
                port=config.api_port,
                allowed_origins=config.api_allowed_origins or None,
                tls_cert=config.api_tls_cert,
                tls_key=config.api_tls_key,
                audit_path=config.logs_dir / "api-audit.jsonl",
            )
            if configured_token is None:
                print(f"Generated one-run API token: {api_token}")
            print(f"BitClone API listening at {server.url}")
            try:
                server.run()
            except KeyboardInterrupt:
                pass
            return 0
        output = _handle_command(node, args)
        _print_output(output, args.json)
        return 0
    except (ValueError, argparse.ArgumentTypeError, RPCError) as e:
        parser.exit(2, f"{parser.prog}: error: {e}\n")
    finally:
        if node is not None:
            node.close()


if __name__ == "__main__":
    sys.exit(main())
