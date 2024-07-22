"""
TxEngine: A class for signing Transactions. Designed for use in a Wallet.
"""
from src.cipher import decode_outpoint, encode_signature, decode_transaction
from src.database import Database
from src.library.ecdsa import sign_transaction
from src.primitive import CompactSize, Endian
from src.tx import Transaction, TxInput, TxOutput
from src.wallet import KeyPair, Wallet


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
        # print(f"TX COPY BEFORE REMOVING SCRIPTSIG: {tx_copy.to_json()}")

        # Remove all scriptsigs from the inputs
        for i in tx_copy.inputs:
            i.scriptsig = bytes()
            i.scriptsig_size = CompactSize(0)

        # print(f"TX COPY AFTER REMOVING SCRIPTSIG: {tx_copy.to_json()}")

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


# --- TESTING
from src.library.hash_func import hash256
from src.cipher import encode_script

if __name__ == "__main__":
    db = Database()
    w = Wallet()
    pt1data = "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000"
    pt2data = "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000"
    pt1 = decode_outpoint(pt1data)
    pt2 = decode_outpoint(pt2data)
    utxo1 = db.get_utxo(pt1)
    utxo2 = db.get_utxo(pt2)
    # print(utxo1.to_json())
    # print(utxo2.to_json())
    input1 = TxInput(pt1, "", 0xFFFFFFFF)
    input2 = TxInput(pt2, "", 0xFFFFFFFF)
    pubkeyhash = hash256(w.compressed_public_key)
    _asm = ["OP_DUP", "OP_HASH160", pubkeyhash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    scriptpubkey = encode_script(_asm)

    output1 = TxOutput(120000, scriptpubkey)
    tx = Transaction([input1, input2], [output1])
    e = TxEngine(db, w.keypair)
    print(f"TX: {tx.to_json()}")
    for n in range(tx.input_count.num):
        sig = e.get_legacy_signature(tx, n)
        _scriptsig = [""]

    print(f"TXSIGNED: {tx.to_json()}")
