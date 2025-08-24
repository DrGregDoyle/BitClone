"""
The function used to calculate a short txid
"""
from siphash import SipHash24

from src.backup.crypto import sha256


def get_short_txid(txid: bytes, block_header: bytes):
    """
    Calculate a short transaction ID using SipHash24

    Args:
        txid: Transaction ID (32 bytes)
        block_header: Block header (80 bytes)

    Returns:
        6-byte short transaction ID
    """
    # 1. Get the SINGLE sha256 hash of the block header
    block_hash = sha256(block_header)

    # 2. Extract the first 16 bytes of block_hash for SipHash24 key
    # The SipHash24 constructor expects a 16-byte key
    sip_key = block_hash[:16]

    # 3. Run SipHash24 with the txid as input and block_hash key
    sip_hash = SipHash24(secret=sip_key, s=txid).digest()

    # 4. Drop the 2 most significant bytes from SipHash output to make it 6 bytes
    return sip_hash[:6]


# --- TESTING
if __name__ == "__main__":
    # Use proper sized test data
    test_txid = bytes.fromhex("deadbeef" * 8)  # 32 bytes (256 bits)
    test_blockheader = bytes.fromhex("deadbeef" * 20)  # 80 bytes (block header size)

    test_short_txid = get_short_txid(test_txid, test_blockheader)
    print(f"TEST TXID: {test_txid.hex()}")
    print(f"TEST BLOCK HEADER: {test_blockheader.hex()}")
    print(f"TEST SHORT TXID: {test_short_txid.hex()}")
    print(f"SHORT TXID LENGTH: {len(test_short_txid)} bytes")
