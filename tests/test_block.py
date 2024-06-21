"""
Testing Block and related classes
"""
from src.block import Header, decode_header
from src.utility import *


def test_header():
    # Get variables
    prev_block = random_hash256()
    merkle_root = random_hash256()
    time = random_integer(4)
    target = random_integer(4)
    nonce = random_integer(4)
    version = random_integer(4)

    random_header = Header(
        prev_block=prev_block,
        merkle_root=merkle_root,
        timestamp=time,
        target=target,
        nonce=nonce,
        version=version
    )
    constructed_header = decode_header(random_header.encoded)
    assert constructed_header.encoded == random_header.encoded
