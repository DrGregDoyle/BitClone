"""
The Miner class
"""
from src.block import Block
from src.library.data_handling import bits_to_target_int
from src.logger import get_logger

logger = get_logger(__name__)


class Miner:

    def __init__(self):
        self.is_mining = False

    def mine_block(self, block: Block):
        self.is_mining = True

        target = bits_to_target_int(block.bits)

        while block.header.block_id_num > target and self.is_mining:
            block.increment()
            # logger.debug(f"BLOCK HEADER ID HEX: {block.header.block_id.hex()}")
            # logger.debug(f"BLOCK HEADER NUM: {block.header.block_id_num}")
            # logger.debug(f"TARGET INT: {target}")
            # logger.debug(f"DIFFERENCE: {block.header.block_id_num - target}")
            # logger.debug(f"----------")

        # Mining done or interrupted
        return block if self.is_mining else None

    def stop_mining(self):
        self.is_mining = False


# -- TESTING
from secrets import token_bytes, randbits
from src.library.data_handling import target_to_bits, target_to_bits_from_hex
from src.tx import Transaction, Input, Output

if __name__ == "__main__":
    target_hex = "00ff000000000000000000000000000000000000000000000000000000000000"
    target_bytes = bytes.fromhex(target_hex)

    print(f"BITS FROM TARGET: {target_to_bits_from_hex(target_hex)}")

    # Create minimal tx
    dummy_input = Input(
        txid=token_bytes(32),
        vout=randbits(32),
        script_sig=token_bytes(20),
        sequence=randbits(32)
    )

    dummy_output = Output(
        amount=randbits(64),
        script_pubkey=token_bytes(20)
    )

    dummy_tx = Transaction(
        inputs=[dummy_input],
        outputs=[dummy_output]
    )

    # Create dummy block
    prev_block = token_bytes(32)
    txs = [dummy_tx]
    timestamp = randbits(32)
    bits = target_to_bits(target_bytes)
    nonce = 0
    version = 2

    test_block = Block(prev_block, txs, timestamp, bits, nonce, version)
    print(f"TEST BLOCK: {test_block.to_json()}")

    miner = Miner()
    new_block = miner.mine_block(test_block)
    print(f"NEW BLOCK: {new_block.to_json()}")
