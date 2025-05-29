"""
The TxEngine class - Used for signing a transaction

NOTES:
    - Signatures are designed with an output in mind. They are designed to unlock an output.
    - Hence a legacy, segwit or taproot signature will be used depending ont the type of output referenced.
"""

from src.crypto import hash256, ecdsa, verify_ecdsa, sha256, tagged_hash_function, HashType, ORDER, \
    generator_exponent, PRIME, get_pt_from_x, scalar_multiplication, add_points
from src.data import write_compact_size, encode_der_signature, to_little_bytes, get_public_key_point, \
    decode_der_signature
from src.logger import get_logger
from src.script.sighash import SigHash
from src.tx import Transaction, Input, UTXO

logger = get_logger(__name__)


# HASHTYPE = HashType.SHA256


class SignatureEngine:
    """
    A class used to sign inputs, and construct message hashes for signing
    """
    PUBLICKEY_BYTES = 32
    BIP340_ARRAY = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    ANYONECANPAY_HASHES = [
        SigHash.ALL_ANYONECANPAY,
        SigHash.NONE_ANYONECANPAY,
        SigHash.SINGLE_ANYONECANPAY
    ]

    # --- Utility functions
    def _remove_scriptsig(self, tx: Transaction) -> Transaction:
        # Remove all scriptsigs from the inputs
        for i in tx.inputs:
            i.script_sig = bytes()
            i.script_sig_size = write_compact_size(0)
        return tx

    def _encode_outpoint(self, _input: Input):
        return _input.txid + to_little_bytes(_input.vout, Input.VOUT_BYTES)

    def _handle_extension(self):
        pass

    def _serialize_script(self, script: bytes) -> bytes:
        """
        Returns the compact size encoding of len(script) + script
        """
        return write_compact_size(len(script)) + script

    # --- SigHash construction
    def get_legacy_sighash(self, tx: Transaction, input_index: int, script_pubkey: bytes, sighash_flag: int) -> bytes:
        """
        Computes legacy message_hash for signing:
            1. Remove all existing script_sigs
            2. Put the script_pubkey from referenced output in the script_sig for the input.
            3. Append the sighash byte(s) at the end of the serialized tx data
            4. Hash the serialized tx data
        """
        # Create tx_copy
        tx_copy = Transaction.from_bytes(tx.to_bytes())

        # 1. Remove all existing script_sigs
        tx_copy = self._remove_scriptsig(tx_copy)

        # 2. Insert script_pubkey into input
        tx_copy.inputs[input_index].script_pubkey = script_pubkey
        tx_copy.inputs[input_index].script_sig_size = write_compact_size(len(script_pubkey))

        #  3. Append the sighash byte(s) at the end of the serialized tx data
        sighash = SigHash(sighash_flag)
        data = tx_copy.to_bytes() + sighash.for_hashing()

        # 4. Return message hash
        return hash256(data)

    def get_segwit_sighash(self, tx: Transaction, input_index: int, script_code: bytes, amount: int, sighash_flag:
    int) -> bytes:
        """
        We obtrain the segwit pre-image using the following formula:
            version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) 
            + locktime + sighash
        We then return the hash256 value of this pre-image
        """

        # Version
        version = to_little_bytes(tx.version, Transaction.VERSION_BYTES)

        # hash256(inputs)
        inputs = b''.join([self._encode_outpoint(txin) for txin in tx.inputs])
        hashed_inputs = hash256(inputs)

        # hash256(sequences)
        sequences = b''.join([to_little_bytes(txin.sequence, Input.SEQ_BYTES) for txin in tx.inputs])
        hashed_sequences = hash256(sequences)

        # input
        temp_input = tx.inputs[input_index]
        tx_input = self._encode_outpoint(temp_input)

        # amount
        amount = to_little_bytes(amount, Transaction.AMOUNT_BYTES)

        # sequence
        sequence = to_little_bytes(temp_input.sequence, Input.SEQ_BYTES)

        # hash256(outputs)
        outputs = b''.join([txout.to_bytes() for txout in tx.outputs])
        hashed_outputs = hash256(outputs)

        # locktime
        locktime = to_little_bytes(tx.locktime, Transaction.LOCKTIME_BYTES)

        # sighash
        sighash = SigHash(sighash_flag)

        # construct message and return message hash
        data = (version + hashed_inputs + hashed_sequences + tx_input + script_code + amount + sequence +
                hashed_outputs + locktime + sighash.for_hashing())
        return hash256(data)

    def get_taproot_sighash(self, tx: Transaction, input_index: int, utxos: list[UTXO],
                            extension: bytes = None, annex_present: bool = False, hash_type: SigHash = None) -> bytes:
        """
        sighash epoch + common signature message + extension

        extension = False | key path spend
        extension = True | script path spend
        """
        # Get hash type
        hash_type = SigHash.DEFAULT if hash_type is None else hash_type

        # Get data
        sighash_epoch = b'\x00'
        hash_byte = hash_type.to_byte()
        version = to_little_bytes(tx.version, Transaction.VERSION_BYTES)
        locktime = to_little_bytes(tx.locktime, Transaction.LOCKTIME_BYTES)

        # sha256(inputs)
        inputs = b''.join([self._encode_outpoint(txin) for txin in tx.inputs])
        hashed_prevouts = sha256(inputs)

        # sha256(amounts)
        amounts = b''.join([to_little_bytes(utxo.amount, Transaction.AMOUNT_BYTES) for utxo in utxos])
        hashed_amounts = sha256(amounts)

        # sha256(scriptpubkeys)
        scriptpubkeys = b''.join([self._serialize_script(utxo.script_pubkey) for utxo in utxos])
        hashed_scriptpubkeys = sha256(scriptpubkeys)

        # sha256(sequences)
        sequences = b''.join([to_little_bytes(txin.sequence, Transaction.SEQ_BYTES) for txin in tx.inputs])
        hashed_sequences = sha256(sequences)

        # sha256(outputs)
        outputs = b''.join([txout.to_bytes() for txout in tx.outputs])
        hashed_outputs = sha256(outputs)

        # spend_type
        spend_type_num = (2 if extension else 0) + (1 if annex_present else 0)
        spend_type = to_little_bytes(spend_type_num, 1)

        # input values
        indexed_input = tx.inputs[input_index]
        indexed_utxo = utxos[input_index]
        txin_outpoint = self._encode_outpoint(indexed_input)
        txin_amount = to_little_bytes(indexed_utxo.amount, Transaction.AMOUNT_BYTES)
        txin_scriptpubkey = indexed_utxo.script_pubkey
        txin_sequence = to_little_bytes(indexed_input.sequence, Input.SEQ_BYTES)

        # input_index
        input_index_bytes = to_little_bytes(input_index, 4)  # Hardcoded Index bytes

        # hash annex
        hash_annex = b''
        if annex_present:
            pass

        # extension
        extension = b'' if extension is None else extension

        # hash_single_output
        hash_single_output = sha256(indexed_utxo.to_output_bytes())

        # common signature message
        comsig_message = hash_byte + version + locktime

        # add more based on sighash
        if hash_type not in self.ANYONECANPAY_HASHES:
            comsig_message += hashed_prevouts + hashed_amounts + hashed_scriptpubkeys + hashed_sequences
            if hash_type == SigHash.ALL:
                comsig_message += hashed_outputs
            comsig_message += spend_type + input_index_bytes + hash_annex
            if hash_type == SigHash.SINGLE:
                comsig_message += hash_single_output
        else:
            comsig_message += spend_type + txin_outpoint + txin_amount + txin_scriptpubkey + txin_sequence + hash_annex

        # Return taggedhash
        return tagged_hash_function(sighash_epoch + comsig_message + extension, b'TapSighash', HashType.SHA256)

    ### === ECDSA === ###

    # --- Sign Message
    def sign_message(self, private_key: int, message_hash: bytes, sighash_flag: int) -> bytes:
        """
        Given a private key, a message hash and a sighash flag, we create a DER-encoded ECDSA signature with attached
        sighash byte
        """
        # Sign the message hash using ECDSA (uses low-s value)
        (r, s) = ecdsa(private_key, message_hash)

        # DER encode the signature
        der_signature = encode_der_signature(r, s)

        # Append sighash byte and return for use in script sig
        return der_signature + SigHash(sighash_flag).to_byte()

    # --- Verify Signature
    def verify_sig(self, signature: bytes, pubkey: bytes, message_hash: bytes) -> bool:
        """
        Given a DER-encoded signature, the pubkey and message hash, we verify the ecdsa signature
        """
        # Get pubkey as integer tuple
        pubkey_point = get_public_key_point(pubkey)

        # Decode DER signature
        sig_tuple = decode_der_signature(signature)

        # Return verification bool
        return verify_ecdsa(sig_tuple, message_hash, pubkey_point)

    ### === SCHNORR === ###
    def schnorr_signature(self, private_key: int, message: bytes, auxiliary_bits: bytes = BIP340_ARRAY) -> bytes:
        # Curve setup
        n = ORDER
        hashtype = HashType.SHA256

        # Check that private key is < n
        if private_key >= n:
            raise ValueError("Given private key must be less than number of rational points on the curve")

        # Calculate public key - Negate private_key if necessary
        x, y = generator_exponent(private_key)
        if y % 2 != 0:
            private_key = n - private_key

        # Create private nonce
        aux_rand_hash = tagged_hash_function(encoded_data=auxiliary_bits, tag=b"BIP0340/aux", function_type=hashtype)

        # XOR private key with aux_rand_hash
        nonce_input_value = private_key ^ int.from_bytes(aux_rand_hash, byteorder="big")

        # Create final private nonce
        nonce_input_bytes = nonce_input_value.to_bytes(32, "big") + x.to_bytes(32, "big") + message
        private_nonce_bytes = tagged_hash_function(encoded_data=nonce_input_bytes, tag=b"BIP0340/nonce",
                                                   function_type=hashtype)
        private_nonce = int.from_bytes(private_nonce_bytes, byteorder="big") % n

        # Calculate public nonce - Negate private_nonce if necessary
        px, py = generator_exponent(private_nonce)
        if py % 2 != 0:
            private_nonce = n - private_nonce

        # Calculate the challenge
        challenge_input_bytes = px.to_bytes(32, "big") + x.to_bytes(32, "big") + message
        challenge_bytes = tagged_hash_function(encoded_data=challenge_input_bytes, tag=b"BIP0340/challenge",
                                               function_type=hashtype)
        challenge = int.from_bytes(challenge_bytes, byteorder="big") % n

        # Construct signature
        r = px
        s = (private_nonce + challenge * private_key) % n

        # Return 64 byte signature
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def verify_schnorr_signature(self, public_key_x: int, message: bytes, signature: bytes) -> bool:
        # Verify signature is 64 bytes
        if len(signature) != 64:
            raise ValueError("Given signature is not 64 bytes.")

        # Curve Setup
        n = ORDER
        p = PRIME
        hashtype = HashType.SHA256

        # Convenience
        x = public_key_x

        # Verify x value restrictions
        if x > p:
            raise ValueError("Given x coordinate doesn't satisfy value restrictions")

        # Calculate even y point
        public_key = get_pt_from_x(x)

        # Extract signature parts
        r, s = signature[:32], signature[32:]
        num_r, num_s = int.from_bytes(r, "big"), int.from_bytes(s, "big")

        logger.debug(f"Recovered R: {hex(num_r)[2:]}")
        logger.debug(f"Recovered S: {hex(num_s)[2:]}")

        # Verify signatures values
        errors = {
            "r < p": num_r < p,
            "s < n": num_s < n
        }

        if not all(errors.values()):
            raise ValueError(f"One or more signature values is invalid: {errors}")

        # Calculate the challenge
        challenge_data = num_r.to_bytes(32, "big") + x.to_bytes(32, "big") + message

        # hex_to_bytes(r, hex(x), message.hex())
        challenge_bytes = tagged_hash_function(encoded_data=challenge_data, tag=b"BIP0340/challenge",
                                               function_type=hashtype)
        challenge = int.from_bytes(challenge_bytes, byteorder="big") % n

        # Verify the signature
        point1 = generator_exponent(num_s)
        point2 = scalar_multiplication((n - challenge), public_key)
        point3 = add_points(point1, point2)
        return point3[0] == num_r
