"""
Methods for Schnorr signatures
"""
from typing import Union

from src.library.data_handling import Data
from src.library.ecc import secp256k1
from src.library.hash_functions import tagged_hash_function, HashType
from src.logger import get_logger

logger = get_logger(__name__)

HASHTYPE = HashType.SHA256

# Type aliases for better readability
KeyType = Union[int, str, bytes, Data]
MessageType = Union[str, bytes, Data]


def schnorr_signature(private_key: KeyType, message: MessageType, auxiliary_bits: KeyType = 1):
    # Curve setup
    curve = secp256k1()
    n = curve.order

    # Data setup
    private_key = Data(private_key).num  # integer
    message = Data(message)
    auxiliary_bits = Data(auxiliary_bits)

    # Check that private key is < n
    if private_key >= n:
        raise ValueError("Given private key must be less than number of rational points on the curve")

    # Calculate public key - Negate private_key if necessary
    x, y = curve.multiply_generator(private_key)
    if y % 2 != 0:
        private_key = n - private_key

    logger.debug(f"Private key: {hex(private_key)}")
    logger.debug(f"Public key x: {hex(x)}")
    logger.debug(f"Public key y: {hex(y)}")

    # Create private nonce
    aux_rand_hash = tagged_hash_function("BIP0340/aux", auxiliary_bits, hash_type=HASHTYPE)
    logger.debug(f"Aux Rand Hash: 0x{aux_rand_hash.hex}")

    # XOR private key with aux_rand_hash
    t = private_key ^ aux_rand_hash.num
    logger.debug(f"Private key XOR aux_rand_hash: {hex(t)}")

    # Create final private nonce
    hex_data = hex(t)[2:] + hex(x)[2:] + message.hex
    private_nonce = tagged_hash_function("BIP0340/nonce", hex_data, hash_type=HASHTYPE).num % n
    logger.debug(f"Private Nonce: {hex(private_nonce)}")

    # Calculate public nonce - Negate private_nonce if necessary
    px, py = curve.multiply_generator(private_nonce)
    if py % 2 != 0:
        private_nonce = n - private_nonce
    logger.debug(f"Public nonce x: {hex(px)}")
    logger.debug(f"Public nonce y: {hex(py)}")
    logger.debug(f"Private nonce after negation if necessary: {hex(private_nonce)}")

    # Calculate the challenge
    challenge_data = hex(px)[2:] + hex(x)[2:] + message.hex
    challenge = tagged_hash_function("BIP0340/challenge", challenge_data, HASHTYPE).num % n

    # Construct signature
    r = px
    s = (private_nonce + challenge * private_key) % n

    # Return 64 byte hex string composed of two 32 byte hex strings from r and s
    return format(r, "064x") + format(s, "064x")  # 64 hex chars = 32 bytes


def verify_schnorr_signature(public_key_x: KeyType, message: MessageType, signature: str) -> bool:
    # Verify signature is 128 characters == 64 bytes
    if len(signature) != 128:
        raise ValueError("Given signature is not 64 bytes.")

    # Curve Setup
    curve = secp256k1()
    n = curve.order
    p = curve.p

    # Data setup
    x = Data(public_key_x).num  # Integer
    message = Data(message)

    # Verify x value restrictions
    if x > p:
        raise ValueError("Given x coordinate doesn't satisfy value restrictions")

    # Calculate even y point
    y = curve.find_y_from_x(x)
    if y % 2 != 0:
        y = p - y
    public_key = (x, y)

    # Extract signature parts
    r, s = signature[:64], signature[64:]
    sig_r = Data(r)
    sig_s = Data(s)

    # Verify signatures values
    errors = {
        "r < p": sig_r.num < p,
        "s < n": sig_s.num < n
    }

    if not all(errors.values()):
        raise ValueError(f"One or more signature values is invalid: {errors}")

    # Calculate the challenge
    challenge_data = sig_r.hex + hex(x)[2:] + message.hex
    challenge = tagged_hash_function("BIP0340/challenge", challenge_data, HASHTYPE).num % n

    # Verify the signature
    point1 = curve.multiply_generator(sig_s.num)
    point2 = curve.scalar_multiplication((n - challenge), public_key)
    point3 = curve.add_points(point1, point2)
    return point3[0] == sig_r.num


if __name__ == "__main__":
    _priv_key = 0xc9043f04ef0a863b11e4ac69fd6400ac85c9b3e5fe1bd360b18a7dfd8cef5650
    _message = "ecf966b56f0280388cce9a01af2e18b77b169706d8af4e16bae0af636212ee9c"
    _x, _ = secp256k1().multiply_generator(_priv_key)
    aux = "a749377421647fc959f4ffec56d66db7c7b8dc8184b2b65bc047dbc8c040436b"
    sig = schnorr_signature(_priv_key, _message, aux)
    print(f"SCHNORR SIGNATURE: {sig}")
    print(f"BYTES: {len(sig) // 2}")
    verified = verify_schnorr_signature(_x, _message, sig)
    print(f"SIGNATURE VERIFIED: {verified}")
