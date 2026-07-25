"""Selected Bitcoin Core vectors supported by Bitclone's current interpreter."""

import json
from pathlib import Path

import pytest

from src.script import ScriptEngine


VECTOR_PATH = Path(__file__).parent / "data" / "bitcoin_core_script_subset.json"
VECTOR_DATA = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "vector",
    VECTOR_DATA["vectors"],
    ids=lambda vector: f"core-{vector['source_index']}-{vector['comment']}",
)
def test_bitcoin_core_script_vector(vector):
    engine = ScriptEngine()
    script_sig = bytes.fromhex(vector["script_sig"])
    script_pubkey = bytes.fromhex(vector["script_pubkey"])

    try:
        script_ok = engine.execute_script(script_sig)
        script_ok = script_ok and engine.execute_script(script_pubkey)
        actual = script_ok and engine.validate_stack(require_clean_stack=False)
    except Exception:
        actual = False

    assert actual is vector["expected"]


def test_bitcoin_core_vector_source_is_pinned():
    assert "e34b8d5a7dcd45e4faa3bb5fdeae64bf049037f6" in VECTOR_DATA["source"]
    assert VECTOR_DATA["license"] == "MIT"
