"""
The TxEngine class - Used for signing a transaction

NOTES:
    - Signatures are designed with an output in mind. They are designed to unlock an output.
    - Hence a legacy, segwit or taproot signature will be used depending ont the type of output referenced.
"""

from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from src.crypto import secp256k1, ecdsa, hash256, hash160, tagged_hash_function, HashType
from src.data import write_compact_size, to_little_bytes, compress_public_key, encode_bech32
from src.db import BitCloneDatabase
from src.logger import get_logger
from src.script import OPCODES, ScriptEngine, BTCNum
from src.tx import Transaction, Output, Input, WitnessItem, Witness, UTXO

logger = get_logger(__name__)


class SigHash(IntEnum):
    ALL = 1
    NONE = 2
    SINGLE = 3
    ALL_ANYONECANPAY = -127  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = -126  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = -125  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding (BTCNum).
        """
        btc_num = BTCNum(int(self.value))
        return btc_num.bytes


class TxEngine:
    """
    A class used to construct transactions
    """
    PUBLICKEY_BYTES = 32

    def __init__(self, db: BitCloneDatabase):
        self.db = db

    def get_legacy_sig(self, private_key: int, tx: Transaction, input_index=0, sighash: SigHash = SigHash.ALL) -> bytes:
        """
        Given a private key, transaction with input to be signed, and corresponding input_index, we return the
        signature for use in the scriptsig for the input.

        Legacy Signing Algorithm:
        --
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
            5. Sign the hashed data using ECDSA
            6. DER encode the signature
            7. Append the sighash byte and return

        """

        # Create copy to not modify original
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # Testing helper
        def test_state(log_state: str, test_tx: Transaction = tx_copy):
            logger.debug(log_state)
            logger.debug(test_tx.to_json())

        test_state("TX COPY")  # Initial copy state before modifications

        # Step 1: Remove existing script_sigs
        tx_copy = self._remove_scriptsig(tx_copy)
        test_state("REMOVE SCRIPTSIG")

        # Step 2: Insert the script_pubkey from the referenced UTXO into the input's script_sig
        ref_input = tx_copy.inputs[input_index]
        ref_utxo = self.db.get_utxo(txid=ref_input.txid, vout=ref_input.vout)

        if not ref_utxo:
            raise ValueError("Referenced UTXO not found.")

        r_txid, r_vout, r_amount, r_script_pubkey, r_spent = ref_utxo
        ref_input.script_sig = bytes(r_script_pubkey)
        ref_input.script_sig_size = write_compact_size(len(ref_input.script_sig))
        test_state("ADD SCRIPT SIG (script_pubkey as placeholder)")

        # Step 3: Get sighash tx data for hashing
        tx_sighash_data = tx.to_bytes() + sighash.to_byte()
        logger.debug("SIGHASH TX DATA")
        logger.debug(f"TYPE: {type(tx_sighash_data)}")
        logger.debug(f"{tx_sighash_data.hex()}")

        # Step 4: Hash the tx_sighash_data
        hashed_tx_data = hash256(tx_sighash_data)
        logger.debug(f"HASHED TX DATA")
        logger.debug(f"TYPE: {type(hashed_tx_data)}")
        logger.debug(f"{hashed_tx_data.hex()}")

        # Step 5: Sign the hashed_tx_data using ECDSA (uses low-s value)
        (r, s) = ecdsa(private_key, hashed_tx_data)
        logger.debug(f"ECDSA TUPLE")
        logger.debug(f"(R,S) = {(r, s)}")

        # Step 6: DER encode the signature
        serialized_signature = encode_der_signature(r, s)

        # Step 7: Append sighash byte and return for use in script sig
        serialized_signature = serialized_signature + sighash.to_byte()
        logger.debug(f"SIGNATURE: {serialized_signature.hex()}")
        return serialized_signature

    def get_segwit_sig(self, private_key: int, tx: Transaction, input_amount: int, input_index=0, nonce: int = 0,
                       sighash: SigHash = SigHash.ALL) -> Transaction:
        """
        Given a private key, transaction with input to be signed, and corresponding input_index, we return the
        transaction with the signed Witness item

        NB: nonce is used for testing. TODO: Remove once testing complete. Use a random nonce each time

        Legacy Signing Algorithm:
        --
            1. Construct the preimage and preimage hash
                - Grab the version field (reusable)
                - Serialize and hash the txids and vouts for the inputs (reusable)
                - Serialize and hash the sequences for the inputs (reusable)
                - Serialize the txid + vout for the input we're signing (not reusable)
                - Create a scriptcode for the input we're signing (not reusable)
                - Get the sequence for the input we're signing (not reusable)
                - Serialize and hash all the outputs (reusable)
                - Grab the locktime
                - preimage = version + hash256(inputs) + hash256(sequences) + input_outpoint + scriptcode + amount +
                    sequence + hash256(outputs) + locktime
            2. Sign the preimage hash
            3. DER encode the signature
            4. Append signature hash to DER encoding
            5. Construct Witness for corresponding input
            6. Insert Witness into proper spot in witness list and return tx

        """
        # 1. Construct the pre-image hash
        pre_image_version = to_little_bytes(tx.version, Input.VERSION_BYTES)  # 4 bytes | little-endian

        # Serialize and hash the txids and vouts for the inputs
        # Serialize and hash the sequences for the inputs
        serialized_inputs = b''
        serialized_sequences = b''
        serialized_outputs = b''
        for i in tx.inputs:
            serialized_inputs += i.txid + to_little_bytes(i.vout, Input.VOUT_BYTES)
            serialized_sequences += to_little_bytes(i.sequence, Input.SEQ_BYTES)
        for j in tx.outputs:
            serialized_outputs += j.to_bytes()
        hashed_inputs = hash256(serialized_inputs)
        hashed_sequences = hash256(serialized_sequences)
        hashed_outputs = hash256(serialized_outputs)

        input_to_sign = tx.inputs[input_index]
        serialized_outpoint = b'' + input_to_sign.txid + to_little_bytes(input_to_sign.vout, Input.VOUT_BYTES)

        # Get referenced output
        ref_utxo = UTXO.from_tuple(self.db.get_utxo(txid=input_to_sign.txid, vout=input_to_sign.vout))
        print(f"UTXO: {ref_utxo.to_dict()}")

        # Verify scriptpubkey is in proper format
        script_engine = ScriptEngine()
        parsed_script = script_engine.parse_script(ref_utxo.script_pubkey)
        print(f"PARSED SCRIPT: {parsed_script}")

        is_segwit = parsed_script[0] == OPCODES[0]
        data_len = len(parsed_script[2]) // 2
        is_pushdata = parsed_script[1] == f"OP_PUSHBYTES_{data_len}"
        if not is_segwit or not is_pushdata:
            raise ValueError("Referenced scriptpub key not in proper format")

        # Create scriptcode
        scriptcode = bytes.fromhex("1976a914") + ref_utxo.script_pubkey + bytes.fromhex("88ac")

        # Find the input amount
        amount = to_little_bytes(input_amount, Input.AMOUNT_BYTES)

        # Get the sequence
        input_seq = to_little_bytes(input_to_sign.vout, Input.VOUT_BYTES)

        # Get the locktime
        locktime = to_little_bytes(tx.locktime, Transaction.LOCKTIME_BYTES)

        # Create the preimage
        preimage = (pre_image_version + hashed_inputs + hashed_sequences + serialized_outpoint + scriptcode +
                    amount + input_seq + hashed_outputs + locktime)

        # 2. Sign the preimage hash
        r, s = ecdsa(private_key, preimage)

        # 3. DER encode the signature
        der_encoded_sig = encode_der_signature(r, s)

        # 4. Append sighash byte
        serialized_sig = der_encoded_sig + sighash.to_byte()

        # Construct Witness for signature and compressed public key
        item1 = WitnessItem(serialized_sig)
        item2 = WitnessItem(compress_public_key(private_key))
        ref_witness = Witness([item1, item2])
        print(f"REF WITNESS: {ref_witness.to_json()}")

        # Add Witness to witness position in tx
        tx.witnesses[input_index] = ref_witness
        return tx

    def get_taproot_scriptpubkey(self, private_key: int, merkle_root: bytes, pubkey: bytes = None):
        """
        Returns a P2TR scriptpubkey following the format: OP_1, OP_PUSHBYTES_32, <32-byte tweaked public key>
        """
        curve = secp256k1()
        n = curve.order
        # Get public key point
        if pubkey is None:
            x, y = curve.multiply_generator(private_key)  # Don't need y coordinate
            public_key = x.to_bytes(self.PUBLICKEY_BYTES, "big")
        else:
            # Assume pubkey is x-point on curve
            public_key = pubkey
            x = int.from_bytes(pubkey, "big")
            y = curve.find_y_from_x(x)

        # Check for even y
        if y % 2 != 0:
            y = n - y

        # public_key = x-coordinate in bytes
        print(f"PUBLIC KEY: {public_key.hex()}")

        # Get tweaked public key
        tweaked_data = public_key + merkle_root
        tweak = tagged_hash_function(tweaked_data, b"TapTweak", HashType.SHA256)
        print(f"TWEAK: {tweak.hex()}")

        # Get tweaked point
        tweak_int = int.from_bytes(tweak, "big")
        tweak_point = curve.multiply_generator(tweak_int)
        tweaked_public_key = curve.add_points(tweak_point, (x, y))
        tpk_x, _ = tweaked_public_key
        print(f"TWEAKED PUBLIC KEY: {tpk_x.to_bytes(32, 'big').hex()}")

        # Return scriptsig
        return b'\x51' + b'\x20' + tpk_x.to_bytes(32, 'big')

    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx


def encode_der_signature(r: int, s: int) -> bytes:
    """
    Encodes ECDSA integers r and s into a DER-encoded signature.
    """
    return encode_dss_signature(r, s)


def decode_der_signature(der_sig: bytes) -> tuple[int, int]:
    """
    Decodes a DER-encoded ECDSA signature back into integers r and s.
    """
    return decode_dss_signature(der_sig)


if __name__ == "__main__":
    # r = 41
    # s = 99
    # encode_der_signature(r, s)

    # Setup DB and start your engines
    test_db = BitCloneDatabase()
    test_db._clear_db()
    engine = TxEngine(test_db)

    pubkeyhash = hash160(bytes.fromhex("41"))
    version_byte = bytes.fromhex("00")
    push_data = bytes.fromhex(hex(len(pubkeyhash))[2:])
    segwit_scriptpubkey = version_byte + push_data + pubkeyhash

    # Create tx for utxo
    test_output = Output(100, bytes.fromhex('deadbeef'))
    segwit_output = Output(100, segwit_scriptpubkey)
    test_tx = Transaction(outputs=[test_output, segwit_output])

    test_db.add_utxo(
        txid=test_tx.txid(),
        vout=0,
        amount=test_tx.outputs[0].amount,
        script_pubkey=test_tx.outputs[0].script_pubkey
    )
    test_db.add_utxo(
        txid=test_tx.txid(),
        vout=1,
        amount=test_tx.outputs[1].amount,
        script_pubkey=test_tx.outputs[1].script_pubkey
    )

    # Test UTXOS
    utxos = test_tx.get_utxos()
    print(f"UTXOS in test tx: {[u.to_dict() for u in utxos]}")

    # Create tx to sign
    test_input = Input(test_tx.txid(), 0, bytes.fromhex('babefade'), 0)
    segwit_input = Input(test_tx.txid(), 1, b'', 0)
    input_tx = Transaction(inputs=[test_input, segwit_input], segwit=True)

    # Test engine
    # legacy_sig = engine.get_legacy_sig(private_key=41, tx=input_tx)
    # print(f"LEGACY SIG: {legacy_sig.hex()}")
    # print(f"INPUT TX BEFORE SIGNING: {input_tx.to_json()}")
    # signed_tx = engine.get_segwit_sig(private_key=41, input_amount=75, tx=input_tx, input_index=1)
    # print(f"INPUT TX AFTER SIGNING: {input_tx.to_json()}")
    taproot_scriptpubkey = engine.get_taproot_scriptpubkey(41, bytes.fromhex(
        "b5b72eea07b3e338962944a752a98772bbe1f1b6550e6fb6ab8c6e6adb152e7c"), pubkey=bytes.fromhex(
        "a2fc329a085d8cfc4fa28795993d7b666cee024e94c40115141b8e9be4a29fa4"))
    print(f"SCRIPT PUBKEY: {taproot_scriptpubkey.hex()}")
    taproot_data = taproot_scriptpubkey[2:]
    bech32_encoding = encode_bech32(taproot_data, witver=1)
    print(f"BECH 32 ENCODING: {bech32_encoding}")
