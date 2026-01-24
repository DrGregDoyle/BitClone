"""
Data Messages for P2P networking
"""
from src.blockchain.block import Block
from src.core import SERIALIZED, get_bytes, get_stream, read_compact_size, NetworkDataError
from src.data import write_compact_size
from src.network.message import Message
from src.network.network_data import InvVector
from src.tx import Transaction


class BlockMessage(Message):
    """
    We transmit a Block in a message
    =================================================================================
    |   Name        | data type         | format                            | size  |
    =================================================================================
    |   block       |   Block           |   Block.to_bytes()                |   var |
    =================================================================================
    """
    COMMAND = "block"

    def __init__(self, block: Block):
        super().__init__()  # For magic bytes
        self.block = block

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        block_bytes = get_bytes(byte_stream)
        return cls(Block.from_bytes(block_bytes))

    def to_payload(self):
        return self.block.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return {"block": self.block.to_dict(formatted)}


class TxMessage(Message):
    """
    We transmit a Block in a message
    =====================================================================
    |   Name    |   data type       |   format                  | size  |
    =====================================================================
    |   tx      |   Transaction     |   Transaction.to_bytes()  |   var |
    =====================================================================
    """
    COMMAND = "tx"

    def __init__(self, tx: Transaction):
        super().__init__()  # For magic bytes
        self.tx = tx

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        tx_bytes = get_bytes(byte_stream)
        return cls(Transaction.from_bytes(tx_bytes))

    def to_payload(self):
        return self.tx.to_bytes()

    def payload_dict(self, formatted: bool = True) -> dict:
        return {"tx": self.tx.to_dict(formatted)}


class Inv(Message):
    """
    Sends an Inventory message
    =========================================================================
    |   Name        |   data type   |   format                  |   size    |
    =========================================================================
    |   count       |   int         |   CompactSize             |   var     |
    |   inventory   |   InvVector   |   InvVector.to_bytes()    |   var     |
    =========================================================================
    """
    COMMAND = "inv"
    MAX_ENTRIES = 50000

    def __init__(self, items: list[InvVector]):
        # Validation
        if len(items) > self.MAX_ENTRIES:
            raise NetworkDataError("Inventory list exceeds maximum entries")
        super().__init__()
        self.items = items

    @classmethod
    def from_payload(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # count
        count = read_compact_size(stream)

        # items
        items = [InvVector.from_bytes(stream) for _ in range(count)]

        return cls(items)

    def to_payload(self) -> bytes:
        return write_compact_size(len(self.items)) + b''.join([i.to_bytes() for i in self.items])

    def payload_dict(self, formatted: bool = True) -> dict:
        count = len(self.items)
        inv_dict = {
            f"{x}": self.items[x].to_dict(formatted) for x in range(count)
        }
        return {
            "count": write_compact_size(count).hex() if formatted else count,
            "inventory": inv_dict
        }


# --- TESTING --- #
if __name__ == "__main__":
    sep = "===" * 40

    # --- BlockMessage --- #

    known_block_bytes = bytes.fromhex(
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
    known_block = Block.from_bytes(known_block_bytes)
    test_block_msg = BlockMessage(known_block)

    # --- TX MESSAGE --- #
    known_tx_bytes = bytes.fromhex(
        "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000")
    known_tx = Transaction.from_bytes(known_tx_bytes)
    test_tx_msg = TxMessage(known_tx)

    # --- INV MESSAGE --- #
    known_inv_bytes = bytes.fromhex(
        "0201000000de55ffd709ac1f5dc509a0925d0b1fc442ca034f224732e429081da1b621f55a0100000091d36d997037e08018262978766f24b8a055aaf1d872e94ae85e9817b2c68dc7")
    test_inv_mesg = Inv.from_payload(known_inv_bytes)

    # --- LOGGING --- #
    print(f"=== DATA MESSAGE TESTING ===")
    print(sep)
    print(f"BLOCK MESSAGE: {test_block_msg.to_json()}")
    print(sep)
    print(f"TX MESSAGE: {test_tx_msg.to_json(False)}")
    print(sep)
    print(f"INV MESSAGE: {test_inv_mesg.to_json(False)}")
    print(sep)
