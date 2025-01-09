"""
Methods for testing encoding and decoding
"""
import secrets

from src.library.codec import encode_bech32, decode_bech32
from src.logger import get_logger

logger = get_logger(__name__)

BIT_SIZE = 160

# --- Messages
msg1 = "Bech32 encoded data does not start with required bcq1 for expected P2WPKH locking script"
msg2 = "Decoded P2WPKH Bech32 address doesn't match original byte data"
msg3 = "Decoded P2WPKH Bech32 address doesn't match original hex data"


def test_bech32_codec():
    # Get random data string
    _random_number = secrets.randbits(BIT_SIZE)
    _random_data = hex(_random_number)[2:]
    while len(_random_data) < 40:  # Ensure random data is 20 bytes for bech32 encoding
        _random_data = "0" + _random_data
    logger.debug(f"Random hex data: {_random_data}")
    logger.debug(f"Hex char size: {len(_random_data)}")

    _address = encode_bech32(_random_data)
    logger.debug(f"Bech32 address: {_address}")

    # Verify first 4 characters
    assert _address[:4] == "bc1q", msg1

    # Decode
    _decoded_address = decode_bech32(_address)

    # Verify decoded address agrees with original random data
    assert bytes.fromhex(_decoded_address) == bytes.fromhex(_random_data), msg2
    assert _decoded_address == _random_data, msg3
