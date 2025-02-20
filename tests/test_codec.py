"""
Methods for testing encoding and decoding
"""
from secrets import token_bytes

from src.library.codec import encode_bech32, decode_bech32
from src.logger import get_logger

logger = get_logger(__name__)

# --- Messages
msg1 = "Bech32 encoded data does not start with required bcq1 for expected P2WPKH locking script"
msg2 = "Decoded P2WPKH Bech32 address doesn't match original byte data"


def test_bech32_codec():
    # Get random data string
    _random_data = token_bytes(20)

    # Encode data
    _address = encode_bech32(_random_data)

    # Verify first 4 characters
    assert _address[:4] == "bc1q", msg1

    # Decode
    _decoded_address = decode_bech32(_address)

    # Verify decoded address agrees with original random data
    assert _decoded_address == _random_data, msg2
