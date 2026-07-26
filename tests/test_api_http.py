from contextlib import contextmanager
import json
from queue import Queue
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from src.api import BitCloneHTTPServer, NodeApplicationService
from src.node.node import Node


@contextmanager
def running_api(db_path):
    """Create the thread-affine node and synchronous HTTP server on one thread."""
    started = Queue()

    def run():
        node = Node(db_path=db_path)
        server = BitCloneHTTPServer(NodeApplicationService(node), port=0)
        started.put((server, node.blockchain.tip.block_id[::-1].hex()))
        try:
            server.serve_forever()
        finally:
            server.server_close()
            node.close()

    thread = threading.Thread(target=run, name="bitclone-api-integration")
    thread.start()
    server, genesis_hash = started.get(timeout=5)
    try:
        yield server.url, genesis_hash
    finally:
        server.shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()


def get_json(url):
    with urlopen(url, timeout=5) as response:
        return response, json.loads(response.read())


def test_real_http_api_serves_versioned_status_and_contract(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash):
        response, status = get_json(f"{base_url}/node/status")
        _, openapi = get_json(f"{base_url}/openapi.json")

    assert response.status == 200
    assert response.headers["API-Version"] == "v1"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers.get_content_type() == "application/json"
    assert status["network"] == "mainnet"
    assert status["height"] == 0
    assert "/api/v1/node/status" in openapi["paths"]


def test_real_http_api_returns_block_and_paginated_collections(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, genesis_hash):
        _, block = get_json(f"{base_url}/chain/blocks/{genesis_hash}")
        _, peers = get_json(f"{base_url}/peers?limit=10&offset=0")
        _, mempool = get_json(f"{base_url}/mempool")

    assert block["hash"] == genesis_hash
    assert block["transactions"][0]["outputs"][0]["amount_sats"] == 5_000_000_000
    assert peers == {
        "items": [],
        "page": {"limit": 10, "offset": 0, "count": 0, "total": 0},
    }
    assert mempool["page"]["total"] == 0


def test_real_http_api_returns_stable_error_contract(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash):
        with pytest.raises(HTTPError) as invalid_page:
            urlopen(f"{base_url}/peers?limit=0", timeout=5)
        with pytest.raises(HTTPError) as missing_route:
            urlopen(f"{base_url}/missing", timeout=5)

        invalid_payload = json.loads(invalid_page.value.read())
        missing_payload = json.loads(missing_route.value.read())

    assert invalid_page.value.code == 400
    assert invalid_payload["error"]["code"] == "invalid_parameter"
    assert missing_route.value.code == 404
    assert missing_payload == {
        "error": {
            "code": "route_not_found",
            "message": "The requested API route does not exist",
        }
    }


def test_real_http_api_rejects_mutating_methods(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash):
        request = Request(f"{base_url}/health", data=b"{}", method="POST")
        with pytest.raises(HTTPError) as response:
            urlopen(request, timeout=5)
        payload = json.loads(response.value.read())

    assert response.value.code == 405
    assert response.value.headers["Allow"] == "GET"
    assert payload["error"]["code"] == "method_not_allowed"
