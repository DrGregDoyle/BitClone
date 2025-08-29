"""
Fixtures used in the tests
"""
import pytest

from src.cryptography import secp256k1


@pytest.fixture
def curve():
    return secp256k1()
