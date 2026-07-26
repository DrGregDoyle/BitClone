"""Transport-neutral application services for BitClone operator clients."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.api.contracts import API_PREFIX, API_VERSION, ROUTES, build_openapi_document
from src.node.node import Node
from src.tx.tx import Tx


BITCLONE_VERSION = "0.1.0-dev"
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200


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

    def list_mempool(self, _path: dict, query: dict[str, list[str]]) -> dict[str, Any]:
        limit, offset = _pagination(query)
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
        return _page(resources, limit, offset, len(entries))

    def get_mempool_transaction(self, path: dict[str, str], _query: dict) -> dict[str, Any]:
        display_txid = path["txid"].lower()
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
        }
