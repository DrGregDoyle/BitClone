from contextlib import contextmanager
from http.client import HTTPConnection
import json
from queue import Queue
import threading
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import pytest

from src.api import BitCloneHTTPServer, NodeApplicationService
from src.node.node import Node


API_TOKEN = "test-api-token-with-sufficient-entropy"


@contextmanager
def running_api(db_path, rate_limit=120):
    """Create the thread-affine node and synchronous HTTP server on one thread."""
    started = Queue()

    def run():
        node = Node(db_path=db_path)
        server = BitCloneHTTPServer(
            NodeApplicationService(node),
            api_token=API_TOKEN,
            port=0,
            audit_path=db_path.parent / "api-audit.jsonl",
            rate_limit=rate_limit,
            event_interval=0.05,
        )
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
        yield server.url, genesis_hash, server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()


def get_json(url, authenticated=True, origin=None):
    headers = {}
    if authenticated:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    if origin is not None:
        headers["Origin"] = origin
    request = Request(url, headers=headers)
    with urlopen(request, timeout=5) as response:
        return response, json.loads(response.read())


def test_real_http_api_serves_versioned_status_and_contract(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        response, status = get_json(f"{base_url}/node/status")
        _, openapi = get_json(f"{base_url}/openapi.json", authenticated=False)

    assert response.status == 200
    assert response.headers["API-Version"] == "v1"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers.get_content_type() == "application/json"
    assert status["network"] == "mainnet"
    assert status["height"] == 0
    assert "/api/v1/node/status" in openapi["paths"]


def test_real_http_api_returns_block_and_paginated_collections(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, genesis_hash, _server):
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


def test_real_http_api_serves_authenticated_peer_address_book(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, server):
        server.application._node.address_book.add("192.0.2.10", seen_at=10)

        response, address_book = get_json(f"{base_url}/peers/address-book")
        with pytest.raises(HTTPError) as unauthenticated:
            get_json(f"{base_url}/peers/address-book", authenticated=False)

    assert response.status == 200
    assert address_book["count"] == 1
    assert address_book["peers"][0]["host"] == "192.0.2.10"
    assert address_book["peers"][0]["last_known_message"] is None
    assert unauthenticated.value.code == 401


def test_real_http_api_returns_stable_error_contract(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        with pytest.raises(HTTPError) as invalid_page:
            urlopen(
                Request(
                    f"{base_url}/peers?limit=0",
                    headers={"Authorization": f"Bearer {API_TOKEN}"},
                ),
                timeout=5,
            )
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
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        request = Request(f"{base_url}/health", data=b"{}", method="POST")
        with pytest.raises(HTTPError) as response:
            urlopen(request, timeout=5)
        payload = json.loads(response.value.read())

    assert response.value.code == 405
    assert response.value.headers["Allow"] == "GET"
    assert payload["error"]["code"] == "method_not_allowed"


def test_protected_endpoint_requires_valid_bearer_token(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        with pytest.raises(HTTPError) as missing:
            urlopen(f"{base_url}/node/status", timeout=5)
        with pytest.raises(HTTPError) as invalid:
            urlopen(
                Request(
                    f"{base_url}/node/status",
                    headers={"Authorization": "Bearer incorrect"},
                ),
                timeout=5,
            )

    assert missing.value.code == 401
    assert missing.value.headers["WWW-Authenticate"] == 'Bearer realm="BitClone API"'
    assert json.loads(missing.value.read())["error"]["code"] == "authentication_required"
    assert json.loads(invalid.value.read())["error"]["code"] == "invalid_token"


def test_browser_origin_is_exact_and_csrf_header_is_required_for_mutations(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        origin = base_url.removesuffix("/api/v1")
        response, _payload = get_json(
            f"{base_url}/node/status",
            origin=origin,
        )
        with pytest.raises(HTTPError) as rejected_origin:
            get_json(
                f"{base_url}/node/status",
                origin="https://malicious.example",
            )
        with pytest.raises(HTTPError) as missing_csrf:
            urlopen(
                Request(
                    f"{base_url}/health",
                    data=b"{}",
                    method="POST",
                    headers={"Origin": origin},
                ),
                timeout=5,
            )
        with pytest.raises(HTTPError) as allowed_mutation:
            urlopen(
                Request(
                    f"{base_url}/health",
                    data=b"{}",
                    method="POST",
                    headers={"Origin": origin, "X-BitClone-CSRF": "1"},
                ),
                timeout=5,
            )

    assert response.headers["Access-Control-Allow-Origin"] == origin
    assert rejected_origin.value.code == 403
    assert json.loads(rejected_origin.value.read())["error"]["code"] == "origin_not_allowed"
    assert json.loads(missing_csrf.value.read())["error"]["code"] == "csrf_validation_failed"
    assert allowed_mutation.value.code == 405


def test_http_rate_limit_and_redacted_audit_record(tmp_path):
    audit_path = tmp_path / "api-audit.jsonl"
    with running_api(tmp_path / "node.db", rate_limit=1) as (
        base_url,
        _genesis_hash,
        _server,
    ):
        get_json(f"{base_url}/health", authenticated=False)
        with pytest.raises(HTTPError) as limited:
            get_json(f"{base_url}/health", authenticated=False)

    assert limited.value.code == 429
    assert int(limited.value.headers["Retry-After"]) >= 1
    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        record["event"] == "request_denied"
        and record["code"] == "rate_limit_exceeded"
        for record in records
    )


def test_sse_stream_requires_event_scope_and_delivers_lifecycle_event(tmp_path):
    with running_api(tmp_path / "node.db") as (base_url, _genesis_hash, _server):
        parsed = urlsplit(base_url)
        connection = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        connection.request(
            "GET",
            "/api/v1/events",
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
        response = connection.getresponse()
        lines = []
        while len(lines) < 5:
            line = response.fp.readline().decode("utf-8")
            lines.append(line)
            if line.startswith("data:"):
                break
        connection.close()

        with pytest.raises(HTTPError) as unauthenticated:
            urlopen(f"{base_url}/events", timeout=5)

    body = "".join(lines)
    assert response.status == 200
    assert response.headers.get_content_type() == "text/event-stream"
    assert "event: lifecycle" in body
    assert "data:" in body
    assert unauthenticated.value.code == 401
