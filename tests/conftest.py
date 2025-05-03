"""
Fixtures for test suites
"""
import pytest

from src.crypto import secp256k1
from src.db import BitCloneDatabase
from src.script import ScriptEngine, ScriptSigFactory, ScriptParser, SignatureEngine, ScriptPubKeyFactory


@pytest.fixture(scope="module")
def test_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "test_script_keys.db"
    db = BitCloneDatabase(db_path)
    # optional: seed test data here if needed
    return db


@pytest.fixture
def script_engine():
    return ScriptEngine()


@pytest.fixture
def sig_engine():
    return SignatureEngine()


@pytest.fixture
def parser():
    return ScriptParser()


@pytest.fixture
def curve():
    return secp256k1()


@pytest.fixture
def pubkey_factory():
    return ScriptPubKeyFactory()


@pytest.fixture
def scriptsig_factory():
    return ScriptSigFactory()
