import re

import pytest

from src.api import APIError, NodeApplicationService, ROUTES, build_openapi_document
from src.api.service import RPCError
from src.network.datatypes.network_types import PeerState, Services
from src.network.peer import Peer
from src.network.peer_address_book import PeerSource
from src.node.node import Node


@pytest.fixture
def node(tmp_path):
    instance = Node(db_path=tmp_path / "node.db")
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def service(node):
    return NodeApplicationService(node)


def test_service_status_exposes_operational_data_without_local_paths(service, node):
    result = service.node_status({}, {})

    assert result["network"] == "mainnet"
    assert result["height"] == 0
    assert result["tip"] == node.blockchain.tip.block_id[::-1].hex()
    assert result["block_storage"] == "archival"
    assert result["observed_at"].endswith("Z")
    assert "data_dir" not in result
    assert "db_path" not in result
    assert "core_rpc_password" not in result


def test_service_reports_sync_trust_and_unavailable_future_capabilities(service):
    sync = service.sync_status({}, {})
    trust = service.trust_status({}, {})
    capabilities = service.capabilities({}, {})

    assert sync == {
        "state": "idle",
        "block_height": 0,
        "header_height": 0,
        "progress": 1.0,
        "remote_verification_progress": None,
        "observed_at": sync["observed_at"],
    }
    assert trust["block_data"]["independently_validated"] is True
    assert trust["block_data"]["trust"] == "independently-validated"
    assert trust["remote_source"] is None
    assert capabilities["wallet"]["available"] is False
    assert capabilities["mining"]["available"] is False


def test_local_mempool_is_explicitly_trust_labeled(service):
    result = service.list_mempool({}, {})

    assert result["page"]["total"] == 0
    assert result["source"] == {
        "type": "bitclone-local",
        "trust": "independently-validated",
        "independently_validated": True,
    }


def test_service_formats_block_with_explicit_consensus_and_amount_units(service, node):
    block_hash = node.blockchain.tip.block_id[::-1].hex()

    result = service.get_block({"block_hash": block_hash}, {})

    assert result["hash"] == block_hash
    assert result["height"] == 0
    assert isinstance(result["timestamp_unix"], int)
    assert result["transaction_count"] == 1
    assert result["transactions"][0]["outputs"][0]["amount_sats"] == 5_000_000_000
    assert "amount" not in result["transactions"][0]["outputs"][0]


def test_service_returns_structured_not_found_error_for_unknown_block(service):
    block_hash = "11" * 32

    with pytest.raises(APIError) as error:
        service.get_block({"block_hash": block_hash}, {})

    assert error.value.status == 404
    assert error.value.to_data() == {
        "error": {
            "code": "block_not_found",
            "message": "No block was found for the supplied hash",
            "details": {"block_hash": block_hash},
        }
    }


def test_peer_collection_uses_stable_pagination_and_rfc3339_timestamps(service, node):
    peers = [
        Peer(
            host=f"127.0.0.{index}",
            port=8333,
            state=PeerState.READY,
            protocol_version=70016,
            services=Services.NODE_NETWORK | Services.NODE_WITNESS,
            user_agent="/BitClone:test/",
            last_seen=1_700_000_000 + index,
        )
        for index in range(1, 4)
    ]
    node._ready_peers = {peer.key: peer for peer in peers}

    result = service.list_peers({}, {"limit": ["1"], "offset": ["1"]})

    assert result["page"] == {"limit": 1, "offset": 1, "count": 1, "total": 3}
    assert result["items"][0]["host"] == "127.0.0.2"
    assert result["items"][0]["services"] == int(
        Services.NODE_NETWORK | Services.NODE_WITNESS
    )
    assert result["items"][0]["last_seen_at"].endswith("Z")


def test_peer_address_book_includes_disconnected_peer_diagnostics(service, node):
    peer = Peer("192.0.2.10", 8333)
    node.address_book.add(
        peer.host,
        peer.port,
        source=PeerSource.DNS_SEED,
        seen_at=10,
    )
    node.address_book.record_failure(
        peer,
        source=PeerSource.DNS_SEED,
        failed_at=20,
        message="Connection closed while receiving data",
    )

    result = service.peer_address_book({}, {})

    assert result["count"] == 1
    assert result["default_port"] == 8333
    assert result["peers"][0]["host"] == "192.0.2.10"
    assert result["peers"][0]["sources"] == ["dns_seed"]
    assert result["peers"][0]["last_known_message"] == (
        "Connection closed while receiving data"
    )


def test_transaction_rpc_decodes_reads_and_queries_genesis_outputs(service, node):
    tx = node.blockchain.tip.txs[0]
    raw_hex = tx.to_bytes().hex()
    txid = tx.txid[::-1].hex()
    block_hash = node.blockchain.tip.block_id[::-1].hex()

    decoded = service.dispatch_rpc("decoderawtransaction", [raw_hex])
    raw = service.dispatch_rpc("getrawtransaction", [txid, False, block_hash])
    verbose = service.dispatch_rpc(
        "getrawtransaction",
        {"txid": txid, "verbose": True, "blockhash": block_hash},
    )
    txout = service.dispatch_rpc("gettxout", [txid, 0])

    assert decoded["txid"] == txid
    assert decoded["hex"] == raw_hex
    assert raw == raw_hex
    assert verbose["blockhash"] == block_hash
    assert verbose["is_coinbase"] is True
    assert txout["value"] == 50
    assert txout["amount_sats"] == 5_000_000_000
    assert txout["coinbase"] is True


def test_transaction_rpc_rejects_invalid_or_policy_rejected_transactions(service, node):
    coinbase_hex = node.blockchain.tip.txs[0].to_bytes().hex()

    with pytest.raises(RPCError) as decode_error:
        service.dispatch_rpc("decoderawtransaction", ["deadbeef"])
    with pytest.raises(RPCError) as rejected:
        service.dispatch_rpc("sendrawtransaction", [coinbase_hex])

    assert decode_error.value.code == -22
    assert rejected.value.code == -26
    assert "consensus-invalid" in rejected.value.message


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ({"limit": ["0"]}, "limit must be between"),
        ({"limit": ["201"]}, "limit must be between"),
        ({"limit": ["many"]}, "limit must be an integer"),
        ({"offset": ["-1"]}, "offset must be zero or greater"),
        ({"offset": ["1", "2"]}, "offset may only be provided once"),
    ],
)
def test_collection_pagination_rejects_invalid_values(service, query, message):
    with pytest.raises(APIError, match=message) as error:
        service.list_peers({}, query)

    assert error.value.status == 400
    assert error.value.code == "invalid_parameter"


def test_openapi_is_generated_from_the_dispatch_route_registry():
    document = build_openapi_document()
    operation_ids = {
        operation["get"]["operationId"]
        for operation in document["paths"].values()
    }

    assert document["openapi"] == "3.1.0"
    assert document["info"]["version"] == "v1"
    assert len(document["paths"]) == len(ROUTES)
    assert operation_ids == {route.operation_id for route in ROUTES}
    assert len(operation_ids) == len(ROUTES)
    assert document["components"]["schemas"]["Error"]["required"] == ["error"]
    for route in ROUTES:
        assert route.full_path.startswith("/api/v1")
        for parameter in route.parameters:
            if parameter.location == "path":
                assert parameter.required
                assert re.search(rf"\{{{parameter.name}\}}", route.path)
