"""
Tests for base58 and base58Check encoding
"""
from src.backup.data import encode_base58, decode_base58


def test_base58():
    """
    Given a bytes object with known base58 encoding, we encode the bytes data and compare with the known value. We
    then decode and compare to the original
    """
    # Known values given in hex from learnmeabitcoin.com
    known_hex_encoding = "1yDZG7PMpPrmYHgLhPNg693Kt2e9nAVtb"
    known_hex_data = "000aa1c677870a303b41ce27f924601ee944648d8e504eb098"

    # Convert to bytes
    known_data = bytes.fromhex(known_hex_data)

    # Encode and compare
    encoded_string = encode_base58(known_data)
    assert encoded_string == known_hex_encoding, "Failed base58 encoding for known values"

    # Decode and compare
    decoded_bytes = decode_base58(encoded_string)
    assert decoded_bytes == known_data, "Failed base58 decoding for known values"
