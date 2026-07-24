import base64
import json
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from src.database.bitcoin_core_rpc import BitcoinCoreRPC, BitcoinCoreRPCError


def _response(payload: dict):
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode("utf-8")
    response.__exit__.return_value = False
    return response


def test_rpc_posts_json_with_basic_auth_and_returns_result():
    rpc = BitcoinCoreRPC("http://Skyscraper:8332", username="greg", password="secret")
    with patch(
            "src.database.bitcoin_core_rpc.urlopen",
            return_value=_response({"result": {"blocks": 959194}, "error": None}),
    ) as open_url:
        result = rpc.get_blockchain_info()

    assert result == {"blocks": 959194}
    request = open_url.call_args.args[0]
    payload = json.loads(request.data)
    assert payload["method"] == "getblockchaininfo"
    assert payload["params"] == []
    token = base64.b64encode(b"greg:secret").decode("ascii")
    assert request.headers["Authorization"] == f"Basic {token}"


def test_rpc_uses_cookie_credentials(tmp_path):
    cookie = tmp_path / ".cookie"
    cookie.write_text("__cookie__:token", encoding="utf-8")
    rpc = BitcoinCoreRPC("http://127.0.0.1:8332", cookie_file=cookie)
    with patch(
            "src.database.bitcoin_core_rpc.urlopen",
            return_value=_response({"result": "ok", "error": None}),
    ) as open_url:
        assert rpc.call("help") == "ok"

    token = base64.b64encode(b"__cookie__:token").decode("ascii")
    assert open_url.call_args.args[0].headers["Authorization"] == f"Basic {token}"


def test_rpc_converts_hashes_between_core_display_and_internal_order():
    display_hash = "00" * 31 + "01"
    internal_hash = bytes.fromhex(display_hash)[::-1]
    rpc = BitcoinCoreRPC("http://127.0.0.1:8332", username="user", password="pass")
    rpc.call = MagicMock(side_effect=[display_hash, "deadbeef", "01020304"])

    assert rpc.get_block_hash(7) == internal_hash
    assert rpc.get_block(internal_hash) == bytes.fromhex("deadbeef")
    assert rpc.get_block_header(internal_hash) == bytes.fromhex("01020304")
    assert rpc.call.call_args_list[1].args == ("getblock", display_hash, 0)
    assert rpc.call.call_args_list[2].args == ("getblockheader", display_hash, False)


def test_rpc_surfaces_core_error_without_credentials_in_message():
    rpc = BitcoinCoreRPC("http://127.0.0.1:8332", username="user", password="secret")
    with patch(
            "src.database.bitcoin_core_rpc.urlopen",
            return_value=_response({"result": None, "error": {"code": -5, "message": "Block not found"}}),
    ):
        with pytest.raises(BitcoinCoreRPCError, match=r"-5: Block not found") as error:
            rpc.call("getblock", "00" * 32, 0)

    assert "secret" not in str(error.value)


def test_rpc_wraps_connection_failures():
    rpc = BitcoinCoreRPC("http://127.0.0.1:8332", username="user", password="pass")
    with patch("src.database.bitcoin_core_rpc.urlopen", side_effect=URLError("refused")):
        with pytest.raises(BitcoinCoreRPCError, match="unavailable"):
            rpc.get_blockchain_info()


@pytest.mark.parametrize("url", ["Skyscraper:8332", "file:///tmp/socket"])
def test_rpc_rejects_non_http_urls(url):
    with pytest.raises(ValueError, match="http or https"):
        BitcoinCoreRPC(url, username="user", password="pass")
