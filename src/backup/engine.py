"""
A module for the tx Engine
"""

from src.backup.signature import encode_signature, sign_transaction
from src.database import Database
from src.library.hash_func import hash256
from src.primitive import CompactSize
from src.tx import Transaction, TxInput, Outpoint, UTXO, TxOutput


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
        _value = db.get_utxo(i.outpoint)
        return decode_utxo(i.outpoint.hex + _value)


# --- TESTING

if __name__ == "__main__":
    db = Database(new_db=True)
    _outpt1 = Outpoint(tx_id="fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f", v_out=0)
    _outpt2 = Outpoint(tx_id="ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a", v_out=1)
    _utxo1 = UTXO(outpoint=_outpt1, height=0, amount=0xffff,
                  scriptpubkey="76a91455ae51684c43435da751ac8d2173b2652eb6410588ac")
    _utxo2 = UTXO(outpoint=_outpt2, height=0, amount=0xffff,
                  scriptpubkey="76a91455ae51684c43435da751ac8d2173b2652eb6410588ac")
    db.post_utxo(_utxo1)
    db.post_utxo(_utxo2)

    _amount1 = int("202cb20600000000", 16)
    _amount2 = int("9093510d00000000", 16)
    scriptpubkey1 = "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
    scriptpubkey2 = "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"
    output1 = TxOutput(amount=_amount1, scriptpubkey=scriptpubkey1)
    output2 = TxOutput(amount=_amount2, scriptpubkey=scriptpubkey2)
