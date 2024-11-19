"""
TxEngine: A class for signing Transactions. Designed for use in a Wallet.
"""
from src.backup.library.ecdsa import sign_transaction
from src.cipher import encode_script
from src.cipher import encode_signature, decode_transaction, decode_script
from src.database import Database
from src.tx import Transaction, Witness, WitnessItem
from src.wallet import KeyPair

from src.backup.library.hash_func import hash256
from src.library.primitive import CompactSize, Endian


class TxEngine:
    SIGHASH_BYTES = 4

    def __init__(self, db: Database, kp: KeyPair):
        self.utxos = db
        self.kp = kp

    def get_legacy_signature(self, tx: Transaction, input_index=0, sighash=1) -> bytes:
        """
        We generate an ECDSA signature for use in the scriptsig of the input in the tx at the given input_index.
        Used for: P2PK, P2PKH, P2MS and P2SH
        """
        # Copy Tx
        tx_copy = decode_transaction(tx.hex)

        # Remove all scriptsigs from the inputs
        tx_copy = self._remove_scriptsig(tx_copy)

        # Get refenced input | modifying input modifies tx
        _txinput = tx_copy.inputs[input_index]

        # Get referenced utxo
        temp_outpoint = _txinput.outpoint
        _utxo = self.utxos.get_utxo(temp_outpoint)
        # print(f"UTXO FOR INPUT {input_index}: {_utxo.to_json()}")

        # Put scriptpubkey in input to be signed
        _txinput.scriptsig = _utxo.scriptpubkey
        _txinput.scriptsig_size = CompactSize(len(_utxo.scriptpubkey))
        tx.inputs[input_index] = _txinput

        # Append sighash to tx data
        sighash = Endian(sighash, length=self.SIGHASH_BYTES)
        tx_data = tx_copy.hex + sighash.hex

        # Hash tx_data
        tx_hash = hash256(tx_data)

        # Sign tx_hash
        sig = sign_transaction(tx_hash, self.kp.private_key)
        encoded_sig = encode_signature(sig, sighash.num)  # bytes format

        return encoded_sig

    def get_segwit_signature(self, tx: Transaction, input_index=0, sighash=1):
        """
        Used to create a signature for use in sigwit Script signatures.

        NOTE: tx must have tx.segwit = True
        """
        # Check segwit
        if not tx.segwit:
            raise ValueError(f"Transaction with current tx id {tx.txid} is not segwit.")

        # Copy tx
        txcopy = decode_transaction(tx.hex)

        # Get refenced input | modifying input modifies tx
        _txinput = txcopy.inputs[input_index]

        # Get referenced utxo
        _utxo = self.utxos.get_utxo(_txinput.outpoint)

        # Create scriptcode
        _scriptpubkey = _utxo.scriptpubkey.hex()
        _asm = decode_script(_scriptpubkey)
        _nminus1 = _asm.index("OP_PUSHBYTES_20")
        _pubkeyhash = _asm[_nminus1 + 1]

        # Remove existing script sigs
        txcopy = self._remove_scriptsig(txcopy)

        # Remove witness
        txcopy.witness = []

        # Create pre-image hash
        _version = txcopy.version.hex  # Version
        _prevouts = hash256("".join([i.outpoint.hex for i in txcopy.inputs]))  # Outpoint hash
        _seqhash = hash256("".join([i.sequence.hex for i in txcopy.inputs]))  # Sequence hash
        _outpoint = _txinput.outpoint.hex  # Specific outpoint to be signed
        _scriptcode = f"1976a914{_pubkeyhash}88ac"  # Scriptcode
        _input_amount = _utxo.amount.hex  # Amount on UTXO
        _sequence = _txinput.sequence.hex  # Sequence in TxInput
        _hashoutputs = hash256("".join([i.hex for i in txcopy.outputs]))  # Output hash
        _locktime = txcopy.locktime.hex  # Locktime
        preimage = (_version + _prevouts + _seqhash + _outpoint + _scriptcode + _input_amount + _sequence + _hashoutputs
                    + _locktime)

        # Add sighash
        sighash = Endian(sighash, length=Transaction.SIGHASH_BYTES)
        preimage += sighash.hex

        # Hash preimage
        primage_hash = hash256(preimage)

        # Sign preimage hash
        sig = sign_transaction(primage_hash, self.kp.private_key)
        encoded_sig = encode_signature(sig, sighash.num)  # bytes format
        return encoded_sig

    def sign_tx_p2pkh(self, tx: Transaction, input_index=0, sighash=1):
        """
        We create the scriptsig for the input in the tx referenced by input_index.
        Using script sig [OP_PUSHBYTES_x, <sig>, OP_PUSHBYTES_y, <compressed public key>]
            -where x = len(sig) in bytes, y = len(cpk) in bytes.
        """
        # bytes
        _sig = self.get_legacy_signature(tx, input_index, sighash)
        _cpk = bytes.fromhex(self.kp.compressed_public_key)
        # asm
        _asm = [f"OP_PUSHBYTES_{len(_sig)}", _sig.hex(), f"OP_PUSHBYTES_{len(_cpk)}", self.kp.compressed_public_key]
        scriptsig = bytes.fromhex(encode_script(_asm))
        _input = tx.inputs[input_index]
        _input.scriptsig = scriptsig
        _input.scriptsig_size = CompactSize(len(scriptsig))
        return tx

    def sign_tx_p2wpkh(self, tx: Transaction, input_index=0, sighash=1):
        # Prep tx
        tx.segwit = True

        if not tx.witness:
            tx.witness = [Witness([]) for _ in range(tx.input_count.num)]

        # signature bytes
        _sig = self.get_segwit_signature(tx, input_index, sighash)

        # Witness
        item0 = WitnessItem(_sig.hex())
        item1 = WitnessItem(self.kp.compressed_public_key)
        _witness = Witness([item0, item1])

        # Update and return tx
        tx.witness[input_index] = _witness
        return tx

    def _remove_scriptsig(self, tx: Transaction):
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.scriptsig = bytes()
            i.scriptsig_size = CompactSize(0)
        return tx


# --- TESTING


if __name__ == "__main__":
    empty_item = WitnessItem("")
    empty_witness = Witness([empty_item])
    ew2 = Witness([])
    print(f"EMPTY ITEM: {empty_item.to_json()}")
    print(f"EMPTY WITNESS: {empty_witness.to_json()}")
    print(f"SECOND EMPTY WITNESS: {ew2.to_json()}")
