import json
import os

import pytest

from src.api.events import EventHub, NodeEvent
from src.api.security import (
    APICredential,
    AuditRecorder,
    BearerAuthenticator,
    OriginPolicy,
    SlidingWindowRateLimiter,
    redact_secrets,
)
from src.api.service import APIError


def test_bearer_authentication_enforces_token_and_scope():
    authenticator = BearerAuthenticator(
        [APICredential.from_token("reader", "correct-token", {"read"})]
    )

    principal = authenticator.authenticate("Bearer correct-token", "read")

    assert principal.credential_id == "reader"
    assert principal.scopes == frozenset({"read"})
    with pytest.raises(APIError) as missing:
        authenticator.authenticate(None, "read")
    with pytest.raises(APIError) as invalid:
        authenticator.authenticate("Bearer wrong-token", "read")
    with pytest.raises(APIError) as scope:
        authenticator.authenticate("Bearer correct-token", "events")
    assert missing.value.status == 401
    assert invalid.value.code == "invalid_token"
    assert scope.value.status == 403
    assert authenticator.authenticate(None, None) is None


def test_origin_policy_allows_non_browser_clients_and_exact_origins():
    policy = OriginPolicy({"http://127.0.0.1:8334"})

    assert policy.validate(None) is None
    assert policy.validate("http://127.0.0.1:8334/") == "http://127.0.0.1:8334"
    with pytest.raises(APIError) as error:
        policy.validate("https://malicious.example")
    assert error.value.code == "origin_not_allowed"


def test_rate_limiter_returns_remaining_capacity_and_retry_time():
    now = [100.0]
    limiter = SlidingWindowRateLimiter(
        limit=2,
        window_seconds=10,
        clock=lambda: now[0],
    )

    assert limiter.check("client") == 1
    assert limiter.check("client") == 0
    with pytest.raises(APIError) as limited:
        limiter.check("client")
    assert limited.value.status == 429
    assert limited.value.details["retry_after_seconds"] == 11

    now[0] = 111
    assert limiter.check("client") == 1


def test_recursive_redaction_and_audit_file_permissions(tmp_path):
    audit_path = tmp_path / "api-audit.jsonl"
    audit_path.write_text("", encoding="utf-8")
    audit_path.chmod(0o644)
    recorder = AuditRecorder(audit_path)

    recorder.record(
        "security_test",
        api_token="never-write-this",
        nested={"wallet_seed": "also-secret", "safe": "visible"},
    )

    record = json.loads(audit_path.read_text(encoding="utf-8"))
    assert record["api_token"] == "[REDACTED]"
    assert record["nested"]["wallet_seed"] == "[REDACTED]"
    assert record["nested"]["safe"] == "visible"
    assert os.stat(audit_path).st_mode & 0o777 == 0o600
    assert redact_secrets({"core_rpc_cookie": "/secret", "height": 1}) == {
        "core_rpc_cookie": "[REDACTED]",
        "height": 1,
    }


def test_event_hub_resumes_after_event_id_and_redacts_payloads():
    hub = EventHub(history_size=3)
    first = hub.publish("lifecycle", {"state": "started"})
    second = hub.publish("warning", {"api_token": "secret", "message": "test"})
    subscription = hub.subscribe(last_event_id=first.event_id, heartbeat_seconds=0.01)

    received = next(subscription)

    assert received == second
    assert b"event: warning" in received.to_sse()
    assert b"secret" not in received.to_sse()
    hub.close()


def test_node_event_rejects_non_finite_json():
    event = NodeEvent(1, "warning", {"value": float("nan")})

    with pytest.raises(ValueError):
        event.to_sse()
