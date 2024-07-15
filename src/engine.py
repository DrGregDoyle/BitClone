"""
A module for the tx Engine
"""
from src.cipher import decode_utxo
from src.database import Database
from src.library.hash_func import hash256
from src.primitive import CompactSize
from src.signature import encode_signature, sign_transaction
from src.transaction import Transaction, TxInput, TxOutput
from src.utxo import Outpoint


class Engine:

    def __init__(self, db: Database):
        self.utxos = db

    def legacy_signature(self, tx: Transaction, private_key: int):
        """
        From a tx and a private key we generate an encoded signature suitable for use in construction of sigscript
        for legacy scripts (e.g: P2PK, P2PKH, P2MS, and P2SH)
        """
        # - 1: For each input in the tx, get the associated UTXO and replace the scriptsig in the input with the
        #      scriptpubkey in the utxo
        for i in tx.inputs:
            _outpoint = Outpoint(i.tx_id.hex, i.v_out.num)
            _value = db.get_utxo(_outpoint)
            _utxo = decode_utxo(_outpoint.hex + _value)
            ##TESTING
            print(f"LEGACY SIG UTXO: {_utxo.to_json()}")
            i.scriptsig = _utxo.scriptpubkey
            i.scriptsig_size = CompactSize(len(i.scriptsig))

        # Hash tx data
        _tx_hash = hash256(tx.bytes)

        # return DER-encoded signature
        encoded_sig = encode_signature(
            sig=sign_transaction(_tx_hash, private_key),
            sighash=tx.sighash.num
        )

        return encoded_sig


# --- TESTING
from src.cipher import decode_outpoint

if __name__ == "__main__":
    db = Database()
    outpoints = db.get_outpoints()
    values = db.get_values()
    _outpoint = decode_outpoint(outpoints[0])
    _input = TxInput(tx_id=_outpoint.txid.hex, v_out=_outpoint.v_out.num, scriptsig="")
    _output = TxOutput(1, scriptpubkey="deadbeef")
    tx = Transaction([_input], [_output])
    # print(f"TX BEFORE ENGINE: {tx.to_json()}")
    e = Engine(db)
    _sig = e.legacy_signature(tx, private_key=1)
    print(f"SIGNATURE: {_sig.hex()}")
