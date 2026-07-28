"""Transport-neutral application services for BitClone operator clients."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.api.contracts import API_PREFIX, API_VERSION, ROUTES, build_openapi_document
from src.config import BlockStorageMode
from src.core import NETWORK, ReadError, TransactionError
from src.database.bitcoin_core_rpc import BitcoinCoreRPCError
from src.node.node import Node
from src.tx.tx import Tx


BITCLONE_VERSION = "0.1.0-dev"
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
SATOSHIS_PER_BITCOIN = 100_000_000


class RPCError(Exception):
    """Bitcoin-style JSON-RPC application error."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_data(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message}


class APIError(Exception):
    """A stable application error that HTTP and future transports can render."""

    def __init__(
            self,
            status: int,
            code: str,
            message: str,
            details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details

    def to_data(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        return {"error": error}


def _utc_timestamp(timestamp: float | int | None = None) -> str | None:
    if timestamp is None:
        return None
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _now() -> str:
    return _utc_timestamp(datetime.now(tz=timezone.utc).timestamp())  # type: ignore[return-value]


def _display_hash(value: str, field: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise APIError(400, "invalid_parameter", f"{field} must be hexadecimal") from error
    if len(raw) != 32:
        raise APIError(
            400,
            "invalid_parameter",
            f"{field} must contain exactly 64 hexadecimal characters",
        )
    return raw[::-1]


def _display_hash_for_rpc(value: str, field: str) -> bytes:
    try:
        return _display_hash(value, field)
    except APIError as error:
        raise RPCError(-8, error.message) from error


def _pagination(query: dict[str, list[str]]) -> tuple[int, int]:
    def integer(name: str, default: int) -> int:
        values = query.get(name)
        if not values:
            return default
        if len(values) != 1:
            raise APIError(400, "invalid_parameter", f"{name} may only be provided once")
        try:
            return int(values[0])
        except ValueError as error:
            raise APIError(400, "invalid_parameter", f"{name} must be an integer") from error

    limit = integer("limit", DEFAULT_PAGE_LIMIT)
    offset = integer("offset", 0)
    if not 1 <= limit <= MAX_PAGE_LIMIT:
        raise APIError(
            400,
            "invalid_parameter",
            f"limit must be between 1 and {MAX_PAGE_LIMIT}",
        )
    if offset < 0:
        raise APIError(400, "invalid_parameter", "offset must be zero or greater")
    return limit, offset


def _page(items: list[Any], limit: int, offset: int, total: int) -> dict[str, Any]:
    return {
        "items": items,
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(items),
            "total": total,
        },
    }


def _format_transaction(tx: Tx) -> dict[str, Any]:
    return {
        "txid": tx.txid[::-1].hex(),
        "wtxid": tx.wtxid[::-1].hex(),
        "version": tx.version,
        "locktime": tx.locktime,
        "is_coinbase": tx.is_coinbase,
        "is_segwit": tx.is_segwit,
        "size_bytes": tx.length,
        "virtual_size_vbytes": tx.vbytes,
        "weight_units": tx.wu,
        "inputs": [
            {
                "txid": txin.txid[::-1].hex(),
                "vout": txin.vout,
                "script_sig": txin.scriptsig.hex(),
                "sequence": txin.sequence,
            }
            for txin in tx.inputs
        ],
        "outputs": [
            {
                "index": index,
                "amount_sats": txout.amount,
                "script_pubkey": txout.scriptpubkey.hex(),
            }
            for index, txout in enumerate(tx.outputs)
        ],
        "witness": [witness.to_data()["items"] for witness in tx.witness] if tx.is_segwit else [],
    }


def _format_rpc_transaction(tx: Tx) -> dict[str, Any]:
    """Render the subset of Bitcoin Core's decoded transaction shape we support."""
    vin = []
    for txin in tx.inputs:
        if tx.is_coinbase:
            vin.append({
                "coinbase": txin.scriptsig.hex(),
                "sequence": txin.sequence,
            })
        else:
            vin.append({
                "txid": txin.txid[::-1].hex(),
                "vout": txin.vout,
                "scriptSig": {"asm": "", "hex": txin.scriptsig.hex()},
                "sequence": txin.sequence,
            })
    return {
        "txid": tx.txid[::-1].hex(),
        "hash": tx.wtxid[::-1].hex(),
        "version": tx.version,
        "size": tx.length,
        "vsize": tx.vbytes,
        "weight": tx.wu,
        "locktime": tx.locktime,
        "vin": vin,
        "vout": [
            {
                "value": txout.amount / SATOSHIS_PER_BITCOIN,
                "n": index,
                "scriptPubKey": {
                    "asm": "",
                    "desc": "raw()",
                    "hex": txout.scriptpubkey.hex(),
                    "type": "nonstandard",
                },
            }
            for index, txout in enumerate(tx.outputs)
        ],
        "hex": tx.to_bytes().hex(),
        "is_coinbase": tx.is_coinbase,
        "input_num": len(tx.inputs),
        "output_num": len(tx.outputs),
    }


_MISSING = object()


def _rpc_param(
        params: list[Any] | dict[str, Any],
        index: int,
        name: str,
        default: Any = _MISSING,
) -> Any:
    if isinstance(params, list):
        if index < len(params):
            return params[index]
    elif name in params:
        return params[name]
    if default is _MISSING:
        raise RPCError(-8, f"Missing required parameter: {name}")
    return default


class NodeApplicationService:
    """
    Stable operator-facing boundary around a running ``Node``.

    HTTP handlers call only this class. Consensus, storage, networking, and
    mempool objects remain behind the boundary and can evolve independently.
    """

    def __init__(self, node: Node):
        self._node = node

    def dispatch(
            self,
            operation_id: str,
            path: dict[str, str] | None = None,
            query: dict[str, list[str]] | None = None,
    ) -> dict[str, Any]:
        handler = getattr(self, operation_id, None)
        if handler is None or operation_id.startswith("_"):
            raise APIError(404, "route_not_found", "The requested API route does not exist")
        return handler(path or {}, query or {})

    @staticmethod
    def rpc_required_scope(method: str) -> str:
        return "admin" if method == "sendrawtransaction" else "read"

    def dispatch_rpc(
            self,
            method: str,
            params: list[Any] | dict[str, Any] | None = None,
    ) -> Any:
        if not isinstance(method, str) or not method:
            raise RPCError(-32600, "Invalid Request")
        normalized_params = [] if params is None else params
        if not isinstance(normalized_params, (list, dict)):
            raise RPCError(-32602, "Params must be an array or object")

        unavailable = {
            "getwalletinfo": "Wallet RPC is unavailable until Sprint 11.",
            "listwallets": "Wallet RPC is unavailable until Sprint 11.",
            "getnewaddress": "Wallet RPC is unavailable until Sprint 11.",
            "sendtoaddress": "Wallet RPC is unavailable until Sprint 11.",
            "getbalances": "Wallet RPC is unavailable until Sprint 11.",
            "getmininginfo": "Mining RPC is unavailable until Sprint 10.",
            "getblocktemplate": "Mining RPC is unavailable until Sprint 10.",
            "submitblock": "Mining RPC is unavailable until Sprint 10.",
            "generatetoaddress": "Mining RPC is unavailable until Sprint 10.",
        }
        if method in unavailable:
            raise RPCError(-1, unavailable[method])

        handler = getattr(self, f"_rpc_{method}", None)
        if handler is None:
            raise RPCError(-32601, "Method not found")
        return handler(normalized_params)

    def command_status(self) -> dict[str, Any]:
        """CLI-compatible status through the shared service boundary."""
        return self._node.status()

    def command_chain_tip(self) -> dict[str, Any]:
        entry = self._node.blockchain.db.get_active_tip()
        return {
            "found": entry is not None,
            "tip": self._format_block_index(entry),
        }

    def command_remote_chain_info(self) -> dict[str, Any]:
        info = self._node.remote_blockchain_info()
        return {"configured": info is not None, "blockchain": info}

    def command_block_header(self, display_hash: str) -> dict[str, Any]:
        block_hash = _display_hash_for_rpc(display_hash, "block_hash")
        index_entry = self._node.blockchain.get_block_index(block_hash)
        block = (
            self._node.blockchain.get_block(block_hash)
            if index_entry is not None
            else None
        )
        header = (
            block.get_header()
            if block is not None
            else self._node.blockchain.get_remote_block_header(block_hash)
        )
        if header is None:
            return {"found": False, "block_hash": display_hash}
        return {
            "found": True,
            "height": index_entry.height if index_entry is not None else None,
            "header": header.to_data(),
            "index": self._format_block_index(index_entry),
        }

    def command_block(self, display_hash: str) -> dict[str, Any]:
        block = self._node.blockchain.get_block(
            _display_hash_for_rpc(display_hash, "block_hash")
        )
        if block is None:
            return {"found": False, "block_hash": display_hash}
        return {"found": True, "block": block.to_data()}

    @staticmethod
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

    def _rpc_getblockchaininfo(self, params: list | dict) -> dict[str, Any]:
        if params:
            raise RPCError(-8, "getblockchaininfo takes no parameters")
        status = self._node.status()
        tip = self._node.blockchain.db.get_active_tip()
        remote = (
            self._node.remote_blockchain_info()
            if self._node.config.block_storage is BlockStorageMode.BITCOIN_CORE_REMOTE
            else None
        )
        blocks = remote.get("blocks", status["height"]) if remote else status["height"]
        headers = remote.get("headers", status["best_header_height"]) if remote else status["best_header_height"]
        best_hash = remote.get("bestblockhash", status["tip"]) if remote else status["tip"]
        verification_progress = (
            remote.get("verificationprogress", 0.0)
            if remote
            else (1.0 if headers <= blocks else blocks / max(1, headers))
        )
        return {
            "chain": remote.get("chain") if remote else {
                "mainnet": "main",
                "testnet": "test",
                "regtest": "regtest",
                "signet": "signet",
            }[status["network"]],
            "blocks": blocks,
            "headers": headers,
            "bestblockhash": best_hash,
            "difficulty": remote.get("difficulty") if remote else None,
            "time": remote.get("time") if remote else getattr(self._node.blockchain.tip, "timestamp", 0),
            "mediantime": remote.get("mediantime") if remote else getattr(self._node.blockchain.tip, "timestamp", 0),
            "verificationprogress": verification_progress,
            "initialblockdownload": remote.get("initialblockdownload", False) if remote else blocks < headers,
            "chainwork": remote.get("chainwork") if remote else f"{tip.chainwork if tip else 0:064x}",
            "size_on_disk": remote.get("size_on_disk") if remote else None,
            "pruned": remote.get("pruned", False) if remote else (
                self._node.config.block_storage is BlockStorageMode.PRUNED
            ),
            "warnings": remote.get("warnings", "") if remote else "",
            "bitclone": {
                "block_storage": status["block_storage"],
                "trust": status["block_data"]["trust"],
                "independently_validated": status["block_data"]["independently_validated"],
            },
        }

    def _rpc_getnetworkinfo(self, params: list | dict) -> dict[str, Any]:
        if params:
            raise RPCError(-8, "getnetworkinfo takes no parameters")
        peers = self._node.ready_peers
        return {
            "version": 100,
            "subversion": NETWORK.USER_AGENT,
            "protocolversion": NETWORK.PROTOCOL_VERSION,
            "localservices": f"{0:016x}",
            "localservicesnames": [],
            "localrelay": True,
            "timeoffset": 0,
            "networkactive": self._node.started,
            "connections": len(peers),
            "connections_in": 0,
            "connections_out": len(peers),
            "networks": [],
            "relayfee": self._node.mempool.min_fee / SATOSHIS_PER_BITCOIN,
            "incrementalfee": self._node.mempool.min_fee / SATOSHIS_PER_BITCOIN,
            "localaddresses": [],
            "warnings": "",
        }

    def _rpc_getpeerinfo(self, params: list | dict) -> list[dict[str, Any]]:
        if params:
            raise RPCError(-8, "getpeerinfo takes no parameters")
        return [
            {
                "id": index,
                "addr": f"{peer.host}:{peer.port}",
                "services": f"{int(peer.services or 0):016x}",
                "servicesnames": (
                    [] if peer.services is None else peer.services.name.split("|")
                ),
                "lastsend": int(peer.last_seen),
                "lastrecv": int(peer.last_seen),
                "bytessent": 0,
                "bytesrecv": 0,
                "conntime": int(peer.last_success or peer.last_seen),
                "version": peer.protocol_version or 0,
                "subver": peer.user_agent or "",
                "startingheight": peer.last_block or 0,
                "inbound": False,
                "connection_type": "outbound-full-relay",
            }
            for index, peer in enumerate(self._node.ready_peers)
        ]

    def _rpc_getrawmempool(self, params: list | dict) -> list[str] | dict[str, Any]:
        verbose = _rpc_param(params, 0, "verbose", False)
        if not isinstance(verbose, bool):
            raise RPCError(-3, "verbose must be a boolean")
        if self._uses_remote_mempool():
            try:
                return self._node.core_rpc.get_raw_mempool(verbose)
            except BitcoinCoreRPCError as error:
                raise RPCError(-342, "Bitcoin Core mempool is unavailable") from error
        if not verbose:
            return self._node.mempool.get_txids()
        return {
            txid[::-1].hex(): {
                "vsize": entry.tx.vbytes,
                "weight": entry.tx.wu,
                "time": entry.arrival_time,
                "height": self._node.blockchain.height,
                "fee": entry.fee,
                "vbytes": entry.tx.vbytes,
                "feerate": entry.feerate,
                "ancestor_count": len(entry.ancestors),
                "descendant_count": len(entry.descendants),
                "fees": {
                    "base": entry.fee / SATOSHIS_PER_BITCOIN,
                    "modified": entry.fee / SATOSHIS_PER_BITCOIN,
                    "ancestor": entry.fee / SATOSHIS_PER_BITCOIN,
                    "descendant": entry.fee / SATOSHIS_PER_BITCOIN,
                },
                "depends": [ancestor.tx.txid[::-1].hex() for ancestor in entry.ancestors],
                "spentby": [descendant.tx.txid[::-1].hex() for descendant in entry.descendants],
            }
            for txid, entry in self._node.mempool.mempool.items()
        }

    def _rpc_decoderawtransaction(self, params: list | dict) -> dict[str, Any]:
        raw_hex = _rpc_param(params, 0, "hexstring")
        if not isinstance(raw_hex, str):
            raise RPCError(-3, "hexstring must be a string")
        try:
            tx = Tx.from_bytes(bytes.fromhex(raw_hex))
        except (ValueError, ReadError, TransactionError) as error:
            raise RPCError(-22, f"TX decode failed: {error}") from error
        return _format_rpc_transaction(tx)

    def _rpc_sendrawtransaction(self, params: list | dict) -> str:
        raw_hex = _rpc_param(params, 0, "hexstring")
        if not isinstance(raw_hex, str):
            raise RPCError(-3, "hexstring must be a string")
        try:
            tx = Tx.from_bytes(bytes.fromhex(raw_hex))
        except (ValueError, ReadError, TransactionError) as error:
            raise RPCError(-22, f"TX decode failed: {error}") from error
        if not self._node.submit_tx(tx):
            raise RPCError(-26, "Transaction rejected by BitClone mempool policy")
        return tx.txid[::-1].hex()

    def _rpc_getrawtransaction(self, params: list | dict) -> str | dict[str, Any]:
        display_txid = _rpc_param(params, 0, "txid")
        verbose = _rpc_param(params, 1, "verbose", False)
        display_block_hash = _rpc_param(params, 2, "blockhash", None)
        if not isinstance(display_txid, str):
            raise RPCError(-3, "txid must be a string")
        txid = _display_hash_for_rpc(display_txid, "txid")
        tx = self._node.mempool.get_tx(txid)
        block = None
        if tx is None and display_block_hash is not None:
            if not isinstance(display_block_hash, str):
                raise RPCError(-3, "blockhash must be a string")
            block = self._node.blockchain.get_block(
                _display_hash_for_rpc(display_block_hash, "blockhash")
            )
            if block is not None:
                tx = next((candidate for candidate in block.txs if candidate.txid == txid), None)
        if tx is None:
            raise RPCError(
                -5,
                "No such mempool transaction. Use the blockhash argument for a confirmed transaction.",
            )
        if not isinstance(verbose, (bool, int)):
            raise RPCError(-3, "verbose must be a boolean")
        if not bool(verbose):
            return tx.to_bytes().hex()
        result = _format_rpc_transaction(tx)
        if block is not None:
            result["blockhash"] = block.block_id[::-1].hex()
        return result

    def _rpc_gettxout(self, params: list | dict) -> dict[str, Any] | None:
        display_txid = _rpc_param(params, 0, "txid")
        vout = _rpc_param(params, 1, "n")
        include_mempool = _rpc_param(params, 2, "include_mempool", True)
        if not isinstance(display_txid, str):
            raise RPCError(-3, "txid must be a string")
        if not isinstance(vout, int) or isinstance(vout, bool) or vout < 0 or vout > 0xffffffff:
            raise RPCError(-8, "vout must be an unsigned 32-bit integer")
        if not isinstance(include_mempool, bool):
            raise RPCError(-3, "include_mempool must be a boolean")
        txid = _display_hash_for_rpc(display_txid, "txid")
        utxo = self._node.blockchain.get_utxo(txid + vout.to_bytes(4, "little"))
        if utxo is None:
            return None
        tip = self._node.blockchain.tip
        return {
            "bestblock": tip.block_id[::-1].hex() if tip is not None else "00" * 32,
            "confirmations": max(0, self._node.blockchain.height - utxo.block_height + 1),
            "value": utxo.amount / SATOSHIS_PER_BITCOIN,
            "amount_sats": utxo.amount,
            "outpoint": utxo.outpoint.hex(),
            "block_height": utxo.block_height,
            "scriptPubKey": {
                "asm": "",
                "desc": "raw()",
                "hex": utxo.scriptpubkey.hex(),
                "type": "nonstandard",
            },
            "coinbase": utxo.is_coinbase,
        }

    def _rpc_help(self, params: list | dict) -> str:
        command = _rpc_param(params, 0, "command", None)
        methods = (
            "decoderawtransaction getblockchaininfo getnetworkinfo getpeerinfo "
            "getrawmempool getrawtransaction gettxout sendrawtransaction"
        )
        if command is None:
            return methods
        if not isinstance(command, str):
            raise RPCError(-3, "command must be a string")
        if not hasattr(self, f"_rpc_{command}"):
            raise RPCError(-32601, "Method not found")
        return f"{command} is supported by BitClone's compatibility RPC."

    def api_index(self, _path: dict, _query: dict) -> dict[str, Any]:
        return {
            "name": "BitClone Local Service API",
            "api_version": API_VERSION,
            "links": {
                route.operation_id: route.full_path or API_PREFIX
                for route in ROUTES
            },
        }

    def openapi(self, _path: dict, _query: dict) -> dict[str, Any]:
        return build_openapi_document()

    def events(self, _path: dict, _query: dict) -> dict[str, Any]:
        raise APIError(
            406,
            "event_stream_required",
            "This endpoint must be consumed as a Server-Sent Events stream",
        )

    def health(self, _path: dict, _query: dict) -> dict[str, Any]:
        return {
            "status": "ok",
            "checked_at": _now(),
            "node_started": self._node.started,
        }

    def version(self, _path: dict, _query: dict) -> dict[str, Any]:
        return {
            "bitclone_version": BITCLONE_VERSION,
            "api_version": API_VERSION,
        }

    def capabilities(self, _path: dict, _query: dict) -> dict[str, Any]:
        return {
            "node": {"available": True},
            "chain": {"available": True},
            "peers": {"available": True},
            "mempool": {"available": True},
            "wallet": {
                "available": False,
                "reason": "Wallet operator workflows are planned for Sprint 11.",
            },
            "mining": {
                "available": False,
                "reason": "Consensus-qualified mining workflows are planned for Sprint 10.",
            },
            "block_storage_modes": ["archival", "pruned", "bitcoin-core-remote"],
        }

    def node_status(self, _path: dict, _query: dict) -> dict[str, Any]:
        status = self._node.status()
        return {
            "started": status["started"],
            "network": status["network"],
            "block_storage": status["block_storage"],
            "height": status["height"],
            "tip": status["tip"],
            "best_header_height": status["best_header_height"],
            "best_header": status["best_header"],
            "mempool_size": status["mempool_size"],
            "ready_peers": status["outbound_peers"],
            "target_outbound_peers": status["target_outbound"],
            "banned_peers": status["banned_peers"],
            "mining": status["mining"],
            "observed_at": _now(),
        }

    def sync_status(self, _path: dict, _query: dict) -> dict[str, Any]:
        status = self._node.status()
        block_height = status["height"]
        header_height = status["best_header_height"]
        progress = 1.0 if header_height <= block_height else block_height / header_height
        return {
            "state": status["header_sync"],
            "block_height": block_height,
            "header_height": header_height,
            "progress": max(0.0, min(1.0, progress)),
            "remote_verification_progress": (
                status["remote_source"]["verification_progress"]
                if status["remote_source"] is not None
                else None
            ),
            "observed_at": _now(),
        }

    def trust_status(self, _path: dict, _query: dict) -> dict[str, Any]:
        status = self._node.status()
        return {
            "block_data": status["block_data"],
            "remote_source": status["remote_source"],
            "observed_at": _now(),
        }

    def chain_summary(self, _path: dict, _query: dict) -> dict[str, Any]:
        status = self._node.status()
        tip = self._node.blockchain.db.get_active_tip()
        return {
            "network": status["network"],
            "height": status["height"],
            "tip": status["tip"],
            "best_header_height": status["best_header_height"],
            "best_header": status["best_header"],
            "bits": status["bits"],
            "target": status["target"],
            "chainwork": tip.chainwork if tip is not None else 0,
            "block_storage": status["block_storage"],
        }

    def get_block(self, path: dict[str, str], _query: dict) -> dict[str, Any]:
        display_hash = path["block_hash"].lower()
        block = self._node.blockchain.get_block(_display_hash(display_hash, "block_hash"))
        if block is None:
            raise APIError(
                404,
                "block_not_found",
                "No block was found for the supplied hash",
                {"block_hash": display_hash},
            )
        index = self._node.blockchain.get_block_index(block.block_id)
        return {
            "hash": block.block_id[::-1].hex(),
            "height": index.height if index is not None else None,
            "version": block.version,
            "previous_block": block.prev_block[::-1].hex(),
            "merkle_root": block.merkle_tree.merkle_root[::-1].hex(),
            "timestamp_unix": block.timestamp,
            "bits": block.bits.hex(),
            "nonce": block.nonce,
            "target": block.get_header().target.hex(),
            "weight_units": block.weight,
            "transaction_count": len(block.txs),
            "transactions": [_format_transaction(tx) for tx in block.txs],
        }

    def list_peers(self, _path: dict, query: dict[str, list[str]]) -> dict[str, Any]:
        limit, offset = _pagination(query)
        peers = list(self._node.ready_peers)
        resources = [
            {
                "host": str(peer.host),
                "port": peer.port,
                "state": peer.state.value,
                "protocol_version": peer.protocol_version,
                "services": int(peer.services) if peer.services is not None else None,
                "user_agent": peer.user_agent,
                "last_block": peer.last_block,
                "last_seen_at": _utc_timestamp(peer.last_seen),
                "last_success_at": _utc_timestamp(peer.last_success),
                "fail_count": peer.fail_count,
            }
            for peer in peers[offset:offset + limit]
        ]
        return _page(resources, limit, offset, len(peers))

    def peer_address_book(self, _path: dict, _query: dict) -> dict[str, Any]:
        """Return all known endpoints, including failed and disconnected peers."""
        return self._node.address_book.to_data()

    def list_mempool(self, _path: dict, query: dict[str, list[str]]) -> dict[str, Any]:
        limit, offset = _pagination(query)
        if self._uses_remote_mempool():
            return self._list_remote_mempool(limit, offset)
        entries = list(self._node.mempool.mempool.items())
        resources = [
            {
                "txid": txid[::-1].hex(),
                "fee_sats": entry.fee,
                "virtual_size_vbytes": entry.tx.vbytes,
                "feerate_sats_per_vbyte": entry.feerate,
                "arrival_at": _utc_timestamp(entry.arrival_time),
                "ancestor_count": len(entry.ancestors),
                "descendant_count": len(entry.descendants),
            }
            for txid, entry in entries[offset:offset + limit]
        ]
        return {
            **_page(resources, limit, offset, len(entries)),
            "source": {
                "type": "bitclone-local",
                "trust": "independently-validated",
                "independently_validated": True,
            },
        }

    def get_mempool_transaction(self, path: dict[str, str], _query: dict) -> dict[str, Any]:
        display_txid = path["txid"].lower()
        _display_hash(display_txid, "txid")
        if self._uses_remote_mempool():
            try:
                entry = self._node.core_rpc.get_mempool_entry(display_txid)
                transaction = self._node.core_rpc.get_raw_transaction(display_txid, True)
            except BitcoinCoreRPCError as error:
                raise APIError(
                    404,
                    "transaction_not_found",
                    "The transaction is not present in the trusted Bitcoin Core mempool",
                    {"txid": display_txid},
                ) from error
            return {
                "transaction": transaction,
                **self._format_remote_mempool_entry(display_txid, entry),
                "source": self._remote_mempool_source(),
            }
        tx = self._node.mempool.get_tx(_display_hash(display_txid, "txid"))
        if tx is None:
            raise APIError(
                404,
                "transaction_not_found",
                "The transaction is not present in the mempool",
                {"txid": display_txid},
            )
        entry = self._node.mempool.mempool[tx.txid]
        return {
            "transaction": _format_transaction(tx),
            "fee_sats": entry.fee,
            "feerate_sats_per_vbyte": entry.feerate,
            "arrival_at": _utc_timestamp(entry.arrival_time),
            "source": {
                "type": "bitclone-local",
                "trust": "independently-validated",
                "independently_validated": True,
            },
        }

    def _uses_remote_mempool(self) -> bool:
        return (
            self._node.config.block_storage is BlockStorageMode.BITCOIN_CORE_REMOTE
            and self._node.core_rpc is not None
        )

    @staticmethod
    def _remote_mempool_source() -> dict[str, Any]:
        return {
            "type": "bitcoin-core-remote",
            "trust": "trusted-remote",
            "independently_validated": False,
        }

    @staticmethod
    def _format_remote_mempool_entry(txid: str, entry: dict[str, Any]) -> dict[str, Any]:
        fees = entry.get("fees") or {}
        fee_btc = fees.get("base", entry.get("fee", 0))
        fee_sats = round(float(fee_btc) * SATOSHIS_PER_BITCOIN)
        vsize = int(entry.get("vsize", entry.get("size", 0)))
        return {
            "txid": txid,
            "fee_sats": fee_sats,
            "virtual_size_vbytes": vsize,
            "feerate_sats_per_vbyte": fee_sats / vsize if vsize else 0.0,
            "arrival_at": _utc_timestamp(entry.get("time")),
            "ancestor_count": int(entry.get("ancestorcount", 0)),
            "descendant_count": int(entry.get("descendantcount", 0)),
        }

    def _list_remote_mempool(self, limit: int, offset: int) -> dict[str, Any]:
        try:
            entries = self._node.core_rpc.get_raw_mempool(True)
        except BitcoinCoreRPCError as error:
            raise APIError(
                503,
                "remote_mempool_unavailable",
                "The trusted Bitcoin Core mempool is currently unavailable",
            ) from error
        if not isinstance(entries, dict):
            raise APIError(
                502,
                "invalid_remote_response",
                "Bitcoin Core returned an invalid verbose mempool response",
            )
        ordered_entries = list(entries.items())
        resources = [
            self._format_remote_mempool_entry(txid, entry)
            for txid, entry in ordered_entries[offset:offset + limit]
        ]
        return {
            **_page(resources, limit, offset, len(ordered_entries)),
            "source": self._remote_mempool_source(),
        }

    def event_snapshot(self) -> dict[str, dict[str, Any]]:
        """
        Return bounded in-memory state for the event monitor.

        This deliberately avoids SQLite and remote RPC access because it runs
        independently of the synchronous application-service request thread.
        """
        tip = self._node.blockchain.tip
        ready_peers = self._node.ready_peers
        mempool_txids = tuple(sorted(self._node.mempool.get_txids()))
        return {
            "lifecycle": {
                "started": self._node.started,
            },
            "sync": {
                "state": self._node.header_sync.state.value,
                "block_height": self._node.blockchain.height,
                "header_batches_received": self._node.header_sync.batches_received,
                "headers_received": self._node.header_sync.headers_received,
            },
            "peer": {
                "ready_count": len(ready_peers),
                "peers": [
                    {"host": str(peer.host), "port": peer.port}
                    for peer in ready_peers
                ],
            },
            "block": {
                "height": self._node.blockchain.height,
                "tip": tip.block_id[::-1].hex() if tip is not None else None,
            },
            "mempool": {
                "size": len(mempool_txids),
                "txids": list(mempool_txids),
            },
        }
