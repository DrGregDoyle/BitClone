"""
The Blockchain class
"""

# --- IMPORTS --- #

from src.block import Block
from src.cipher import decode_utxo
from src.database import Database
from src.miner import Miner
from src.parse import bits_to_target, target_to_bits
from src.predicates import Endian
from src.signature import *
from src.transaction import TxInput, TxOutput, Transaction
from src.utxo import Outpoint, UTXO
from src.wallet import HDWallet, ExtendedPrivateKey

# MAX_TARGET = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
TEST_TARGET = 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


# --- CLASSES --- #
class Blockchain:
    INITIAL_BLOCK_SUBSIDY = 50 * pow(10, 8)
    HALVING_NUMBER = 210000

    def __init__(self):
        self.chain = []
        self.height = -1
        self.utxos = Database(new_db=True)

        # Load blocks

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else []

    def add_block(self, candidate_block: Block):
        # Validate block
        block_validated = self.validate_block(candidate_block)

        if not block_validated:
            return False

        # Add block
        self.chain.append(candidate_block)
        self.height += 1

        # -- Update UTXOs / Process Transactions
        # - Consume UTXOs from inputs in each tx
        # - Create new UTXOs from outputs in each tx
        new_utxos = self.create_utxos(candidate_block.txs)
        for utxo in new_utxos:
            self.utxos.post_utxo(utxo)

        # Return True/False
        return True

    def validate_block(self, _block: Block):
        # Verify block_id is smaller than target
        block_target = bits_to_target(_block.header.bits)
        if int(block_target, 16) < int(_block.header.id, 16):
            print("Block ID larger than target")
            return False

        # Verify coinbase transaction
        _coinbase = _block.txs[0]
        coinbase_verified = self.verify_coinbase_tx(_coinbase)
        if not coinbase_verified:
            return False

        # Verify previous id
        if self.height >= 0:
            # natural byte order
            last_known_id = self.last_block.id
            if _block.header.previous_block.hex != last_known_id:
                return False

        return True

    def calculate_block_subsidy(self):
        halving_exp = 0
        halving_height = 0
        while halving_height < self.height:
            halving_height += self.HALVING_NUMBER
            halving_exp += 1
        return self.INITIAL_BLOCK_SUBSIDY // pow(2, halving_exp)

    def create_coinbase_tx(self, scriptpubkey: str, scriptsig=None, fees=None):
        # Input
        tx_id = "0" * 64
        v_out = 0xffffffff
        height = self.height + 1
        height_txt = Endian(height, byte_size=(height.bit_length() + 7) // 8).hex if height != 0 else "00"
        scriptsig = height_txt + scriptsig if scriptsig else height_txt
        sequence = 0
        coinbase_input = TxInput(tx_id, v_out, scriptsig, sequence)

        # Output
        fees = 0 if fees is None else fees
        amount = self.calculate_block_subsidy() + fees
        coinbase_output = TxOutput(amount, scriptpubkey)

        # Tx
        return Transaction(inputs=[coinbase_input], outputs=[coinbase_output], locktime=self.height + 100)

    def verify_coinbase_tx(self, coinbase_tx: Transaction):
        # -- Check inputs
        # Must be only 1 input
        input_num = coinbase_tx.input_count.num
        if input_num > 1:
            print("More than 1 TxInput in Coinbase Transaction")
            return False
        # Txid must be all zeros
        null_id = "0" * 64
        coinbase_input = coinbase_tx.inputs[0]
        if coinbase_input.tx_id.hex != null_id:
            print("Txid in coinbase TxInput not all zeros.")
            return False
        # Vout must be max value (4 bytes)
        max_vout = "f" * 8
        if coinbase_input.v_out.hex != max_vout:
            print("Vout in coinbase TxInput not set to max value.")
            return False

        if self.height < 0:
            return True
        # Genesis block
        # Start of scriptsig
        # height_chars = self.height.bit_length() // 4
        # scriptsig_height = coinbase_input.scriptsig.hex()[:height_chars]
        # scriptsig_int = decode_endian(scriptsig_height)
        # print(f"SCRIPTSIG HEIGHT: {scriptsig_int}")
        # print(f"CURRENT HEIGHT: {self.height}")
        # print(f"ENDIAN HEIGHT: {Endian(self.height).hex}")
        # print(f"BYTE SIZE: {(self.height.bit_length() + 7) // 8}")
        # print(f"HEX HEIGHT: {hex(self.height)}")
        # print(f"SCRIPTSIG: {coinbase_input.scriptsig.hex()}")

        return True

    def create_utxos(self, txs: list):
        utxo_list = []
        for t in txs:
            vout = 0
            for p in t.outputs:
                temp_outpoint = Outpoint(t.hash, vout)
                temp_utxo = UTXO(temp_outpoint, self.height, p.amount.num, p.scriptpubkey.hex())
                utxo_list.append(temp_utxo)
                vout += 1
        return utxo_list


# --- TESTING
from datetime import datetime

if __name__ == "__main__":
    bc = Blockchain()
    w = HDWallet()
    m = Miner()

    xpriv = ExtendedPrivateKey(w.keys.get("receiving"))
    xpriv.new_private_child()
    xpriv.new_public_child()
    xpubkey = xpriv.child_pub.get(0)
    # print(pubkey[:66])//
    pubkey = xpubkey[:66]

    scriptpubkey = scriptpubkey_p2pk(pubkey)
    c_tx = bc.create_coinbase_tx(scriptpubkey)
    # print(c_tx.to_json())
    null_tx = "0" * 64
    time = int(datetime.utcnow().timestamp())
    bits = target_to_bits(format(TEST_TARGET, "064x"))
    genesis_block = Block(previous_block=null_tx, transactions=[c_tx], time=time, bits=bits, nonce=0)
    print(genesis_block.to_json())
    block_added = bc.add_block(genesis_block)
    print(f"BLOCK ADDED?: {block_added}")
    mined_genesis_block = m.mine_block(genesis_block)
    print(f"BLOCK MINED. NONCE: {mined_genesis_block.header.nonce.num}")
    mined_block_added = bc.add_block(mined_genesis_block)
    print(f"MINED BLOCK ADDED: {mined_block_added}")
    # c_tx1 = bc.create_coinbase_tx(scriptpubkey)
    # next_block = Block(previous_block=genesis_block.id, transactions=[c_tx1], time=time, bits=bits, nonce=0)
    # mined_next_block = m.mine_block(next_block)
    # next_block_added = bc.add_block(next_block)
    # print(f"NEXT BLOCK ADDED: {next_block_added}")
    #
    # for b in bc.chain:
    #     print(f"BLOCK {bc.chain.index(b)}: {b.to_json()}")
    outpoint1 = Outpoint(c_tx.hash, v_out=0)
    outpoint2 = bc.utxos.get_utxo(outpoint1)
    print(f"OUTPOINT1: {outpoint1.to_json()}")
    print(f"OUTPOINT2: {outpoint2}")
    recovered_utxo = decode_utxo(outpoint1.hex + outpoint2)
    print(f"RECOVERED UTXO: {recovered_utxo.to_json()}")
