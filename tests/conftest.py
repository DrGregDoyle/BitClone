"""
Fixtures for test suites
"""
import pytest

from src.crypto import secp256k1
from src.db import BitCloneDatabase
from src.script import ScriptEngine, TxEngine, ScriptPubKeyEngine, ScriptSigEngine, ScriptParser


@pytest.fixture(scope="module")
def test_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "test_script_keys.db"
    db = BitCloneDatabase(db_path)
    # optional: seed test data here if needed
    return db


@pytest.fixture
def script_engine(test_db):
    return ScriptEngine(db=test_db)


@pytest.fixture
def tx_engine(test_db):
    return TxEngine(db=test_db)


@pytest.fixture
def pubkey_engine():
    return ScriptPubKeyEngine()


@pytest.fixture
def scriptsig_engine():
    return ScriptSigEngine()


@pytest.fixture
def parser():
    return ScriptParser()


@pytest.fixture
def curve():
    return secp256k1()
