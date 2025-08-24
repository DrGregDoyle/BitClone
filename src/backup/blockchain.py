"""
The Blockchain class
"""
from pathlib import Path

from src.backup.block import Block
from src.backup.data import to_little_bytes
from src.backup.db import BitCloneDatabase, DB_PATH
from src.backup.script import ScriptValidator
from src.backup.tx import Input, Witness, WitnessItem, Output, Transaction


class Blockchain:

    def __init__(self, db_path: Path = DB_PATH):
        # Load DB
        self.db = BitCloneDatabase(db_path)

        # Create script validator
        self.validator = ScriptValidator(self.db)

        # Get block reward
        self.block_reward = 0

    def add_block(self, new_block: Block):
        # Add UTXOS, Txs and Block to DB
        for tx in new_block.txs:
            temp_utxo_list = tx.get_utxos()
            for utxo in temp_utxo_list:
                self.db.add_utxo(utxo)
            self.db.add_transaction(tx.txid(), new_block.id, new_block.timestamp)
        self.db.add_block(
            height=self.height,
            block_hash=new_block.id,
            prev_hash=new_block.prev_block,
            timestamp=new_block.timestamp,
            merkle_root=new_block.merkle_tree.merkle_root,
            nonce=new_block.nonce
        )

    def validate_block(self, block: Block) -> bool:
        """
        Must satisfy the following conditions:
            -All transactions pass validation
            
        """
        # Validate all txs
        for tx in block.txs:
            for n in range(len(tx.inputs)):
                valid_txin = self.validator.validate_utxo(tx, n)
                if not valid_txin:
                    return False
        return True

    def create_coinbase_tx(self, outputs: list[Output], script_sig: bytes = b'', segwit: bool = True):

        # Coinbase elements
        coinbase_input = self._create_coinbase_input(script_sig)
        coinbase_witness = self._create_coinbase_witness()

        # Tx based on segwit
        if segwit:
            coinbase_tx = Transaction([coinbase_input], outputs, [coinbase_witness])
        else:
            coinbase_tx = Transaction([coinbase_input], outputs)
        return coinbase_tx

    def _create_coinbase_input(self, scriptsig: bytes):
        """
        BIP 34 | Current height at start of script_sig
        """
        coinbase_txid = b'\x00' * 32  # txid = all zeros
        cointbase_vout = 0xffffffff  # vout = max value
        coinbase_scriptsig = to_little_bytes(self.height) + scriptsig  # BIP 34
        coinbase_sequence = 0xffffffff  # sequence = max value
        return Input(coinbase_txid, cointbase_vout, coinbase_scriptsig, coinbase_sequence)

    def _create_coinbase_witness(self):
        return Witness([WitnessItem(b'\x00' * 32)])

    @property
    def last_block(self):
        return self.db.get_latest_block()

    @property
    def height(self):
        return self.db.get_block_height()


# --- TESTING
from tests.backup.randbtc_generators import get_random_block

if __name__ == "__main__":
    test_db = Path(__file__).parent / "bitclone_db" / "test.db"
    test_chain = Blockchain(test_db)
    # test_chain.db._clear_db()
    random_block = get_random_block()
    test_chain.add_block(random_block)
    print(f"TEST CHAIN HEIGHT: {test_chain.height}")
    test_coinbase_tx = test_chain.create_coinbase_tx([], b'\x41')
    print(f"COINBASE TX: {test_coinbase_tx.to_json()}")
