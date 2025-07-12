"""
The function used to calculate a short txid
"""
from siphash import SipHash24

from src.crypto import sha256


def get_short_txid(txid: bytes, block_header: bytes):
    # 1. Get the SINGLE sha256 hash of the block header
    block_hash = sha256(block_header)

    # 2. Run SipHash24 with the input being the txid and the keys (k0/k1) set to the first two little-endian 64-bit
    # integers from the block_hash
    k0_bytes = block_hash[:8]  # 64-bit = 8 bytes
    k1_bytes = block_hash[8:16]
    k0 = int.from_bytes(k0_bytes, "little")
    k1 = int.from_bytes(k1_bytes, "little")

    sip_hash = SipHash24(secret=block_hash[:16], s=txid).digest()

    # 3. Drop the 2 most significant bytes from SipHash output to make it 6 bytes
    return sip_hash[:6]


# --- TESTING
if __name__ == "__main__":
    test_txid = bytes.fromhex("deadbeef")
    test_blockheader = bytes.fromhex("deadbeef")

    test_short_txid = get_short_txid(test_txid, test_blockheader)
    print(f"TEST SHORT TXID: {test_short_txid.hex()}")
