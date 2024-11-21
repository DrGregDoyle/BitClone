"""
Methods for Schnorr signatures
"""
from typing import Any

from src.library.data_handling import Data
from src.library.ecc import secp256k1
from src.library.hash_functions import tagged_hash_function, HashType
from src.logger import get_logger

logger = get_logger(__name__)

HASHTYPE = HashType.SHA256


def schnorr_signature(private_key: int | Data | Any, message: Data | Any, auxiliary_bits: Any = 1):
    # Setup
    curve = secp256k1()
    n = curve.order
    priv_key = Data(private_key)
    public_key_point = curve.multiply_generator(priv_key.num)
    message = Data(message)
    aux_rand = Data(auxiliary_bits)
    print(aux_rand.hex)

    # Check that private key is < n
    if priv_key.num >= n:
        raise ValueError("Given private key must be less than number of rational points on the curve")

    # Negate private_key if necessary
    if public_key_point[1] % 2 != 0:
        logger.debug("Negating Private Key")
        priv_key = Data(n - priv_key.num)
        public_key_point = curve.multiply_generator(priv_key.num)

    # Create private nonce
    aux_rand_hash = tagged_hash_function("BIP0340/aux", aux_rand, hash_type=HASHTYPE)
    logger.debug(f"AUX RAND HASH HEX: {aux_rand_hash.hex}")

    # XOR private key with aux_rand_hash
    t = priv_key.num ^ aux_rand_hash.num

    # Create final private nonce
    data_to_hash = Data(t + public_key_point[0] + message.num)
    private_nonce = tagged_hash_function("BIP0340/nonce", data_to_hash, hash_type=HASHTYPE).num % n

    # Calculate public nonce
    public_nonce_point = curve.multiply_generator(private_nonce)

    # Negate private nonce if necessary
    if public_nonce_point[1] % 2 != 0:
        logger.debug("Negating Private Nonce")
        private_nonce = n - private_nonce
        public_nonce_point = curve.multiply_generator(private_nonce)

    # Calculate the challenge
    challenge_data = Data(public_nonce_point[0] + public_key_point[0] + message.num)
    challenge = tagged_hash_function("BIP0340/challenge", challenge_data, HASHTYPE).num % n

    # Construct signature
    r = public_nonce_point[0]
    s = (private_nonce + challenge * private_key) % n

    # Return 64 byte hex string composed of two 32 byte hex strings from r and s
    return format(r, "064x") + format(s, "064x")  # 64 hex chars = 32 bytes


def verify_schnorr_signature(public_key_x: int | str, message: Data | Any, signature: str):
    # Setup
    curve = secp256k1()
    n = curve.order
    message = Data(message)
    pubkey_x = Data(public_key_x)

    # Verify signature is 128 characters == 64 bytes
    if len(signature) != 128:
        raise ValueError("Given signature is not 64 bytes.")

    # Calculate even y point
    temp_y = curve.find_y_from_x(pubkey_x.num)
    pubkey_y = Data(temp_y) if temp_y % 2 == 0 else Data(n - temp_y)
    pubkey = (pubkey_x.num, pubkey_y.num)

    # Extract signature parts
    r, s = signature[:64], signature[64:]
    sig_r = Data(r)
    sig_s = Data(s)

    # Verify signatures values
    if sig_r.num >= curve.p or sig_s.num >= n:
        logger.error(f"Signature error. r < p: {sig_r.num > curve.p}, s < n: {sig_s >= n}")
        raise ValueError("Given signature does not meet value restrictions.")

    # Calculate the challenge
    challenge_data = Data(sig_r.num + pubkey_x.num + message.num)
    challenge = tagged_hash_function("BIP0340/challenge", challenge_data, HASHTYPE).num % n

    # Verify the signature
    point1 = curve.multiply_generator(sig_s.num)
    point2 = curve.scalar_multiplication((n - challenge), pubkey)
    point3 = curve.add_points(point1, point2)
    valid_signature = (point3[0] == sig_r.num)
    print(f'VALID SIGNATURE: {valid_signature}')


if __name__ == "__main__":
    _priv_key = 49097021556540366728351378259471079529932651371354504836784826377767265482141
    _message = "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89"
    _x, _ = secp256k1().multiply_generator(_priv_key)
    aux = "deadbeef"
    sig = schnorr_signature(_priv_key, _message, aux)
    print(f"SCHNORR SIGNATURE: {sig}")
    print(f"BYTES: {len(sig) // 2}")
    verify_schnorr_signature(_x, _message, sig)
