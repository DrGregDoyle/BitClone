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
        # Verify tx is not segwit first
        if tx.segwit:
            return self.segwit_signature(tx, private_key)

        # For each input in the tx
        #       - Get the associated UTXO
        #       - Replace input scriptsig with scriptpubkey from UTXO
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

    def segwit_signature(self, tx: Transaction, private_key: int):
        """
        Used in P2WPKH and P2WSH only.
        """
        # Verify that tx is segwith first
        if not tx.segwit:
            return self.legacy_signature(tx, private_key)

        # Remove witness if it exists
        if tx.witness:
            tx.witness = []

    # def _preimage(self, tx: Transaction, unsigned_input: TxInput):
    #     """
    #     preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence +
    #                 hash256(outputs) + locktime
    #     """
    #     # config
    #     _outpoint_hex = "".join([i.tx_id.hex + i.v_out.hex for i in tx.inputs])
    #     _sequence_hex = "".join([i.sequence.hex for i in tx.inputs])
    #
    #     # version
    #     _v = tx.version.hex
    #
    #     # inputs
    #     _i_hash = hash256(_outpoint_hex)
    #
    #     # sequences
    #     _s_hash = hash256(_sequence_hex)
    #
    #     # input
    #     _i = _outpoint_hex
    #
    #     # scriptcode
    #
    #     # # Get utxos
    #     for i in tx.inputs:
    #         _utxo = self._get_utxo(i)
    #         pubkeyhash = _utxo.scriptpubkey.hex()[4:]  # scriptpubkey has 0014<20-byte hash160(public key)>
    #         scriptcode = f"1976a914{pubkeyhash}88ac"

    def _get_utxo(self, i: TxInput):
        _outpoint = Outpoint(i.tx_id.hex, i.v_out.num)
        _value = db.get_utxo(_outpoint)
        return decode_utxo(_outpoint.hex + _value)


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
