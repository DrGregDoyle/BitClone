"""
Methods for encoding and decoding
"""

from src.library.bech32 import convertbits, bech32_encode, bech32_decode, Encoding
from src.logger import get_logger

logger = get_logger(__name__)


# --- BECH32 ENCODING --- #
def encode_bech32(pubkeyhash: str):
    """
    Returns the Bech32 encoding of the provided public key hash.

    Parameters
    ----------
    pubkeyhash : str
        A hexadecimal string representing the public key hash.

    Returns
    -------
    str
        A Bech32-encoded address.
    """

    # Ensure pubkey_hash is exactly 20 bytes
    if len(pubkeyhash) != 40:
        logger.debug(f"PUBKEY_HASH LENGTH: {len(pubkeyhash)}")
        raise ValueError("P2WPKH pubkey hash must be exactly 20 bytes.")

    # Convert 8-bit data to 5-bit using the reference convertbits function
    converted_data = convertbits(bytes.fromhex(pubkeyhash), 8, 5, pad=False)
    if converted_data is None:
        raise ValueError("Failed to convert data from 8-bit to 5-bit.")

    # Prepend version byte (0x00 for SegWit v0)
    converted_data = [0] + converted_data

    # Submit converted_data using "bc" as hrp
    bech32_address = bech32_encode(hrp="bc", data=converted_data, spec=Encoding.BECH32)

    # Decode to verify checksum
    hrp, decoded_data, spec = bech32_decode(bech32_address)
    if hrp != 'bc' or decoded_data is None:
        raise ValueError("Checksum verification failed.")
    return bech32_address


def decode_bech32(bech32_address: str):
    """
    Given a bech32 address we return the pubkeyhash
    """
    # Use reference bech32_decode function to get hrp, data before encoding, and spec used
    hrp, decoded_data, spec = bech32_decode(bech32_address)

    # Remove prepended version byte
    del decoded_data[0]

    # Convert 5-bit data to 8-bit using the reference convertbits function
    converted_data = convertbits(decoded_data, 5, 8, pad=False)
    logger.debug(f"CONVERTED DATA: {converted_data}")

    # Return hex string of pubkeyhash
    return bytes(converted_data).hex()


if __name__ == "__main__":
    _data = "531331feaf731951a82c8dcd33766af24b04c1c1"
    _address = encode_bech32(_data)
    print(f"ORIGINAL DATA: {_data}")
    print(f"ADDRESS: {_address}")
    print(f'BECH32 encoded type: {type(_address)}')
    _decoded_address = decode_bech32(_address)
    print(f"DECODED ADDRESS: {_decoded_address}")
    assert _decoded_address == _data
