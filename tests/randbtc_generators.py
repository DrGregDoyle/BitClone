"""
Methods for generating random BitClone objects
--

NOTE: SQLITE supports signed 64-bit integers, hence the maximum random value for an integer in the database should be
63 bytes

"""
from random import randint
from secrets import token_bytes, randbits, randbelow

from src.block import Block, BlockHeader
from src.data import InvType
from src.network_utils import PrefilledTransaction
from src.tx import Input, Output, WitnessItem, Witness, Transaction


def get_random_scriptpubkey(scriptpubkey_type: str = None):
    r = randbelow(100)
    if r < 40:  # P2WPKH, P2PKH, P2SH (most common, 22-25 bytes)
        return token_bytes(randbelow(4) + 22)
    elif r < 80:  # P2WSH, P2TR (next most common, 34 bytes)
        return token_bytes(34)
    elif r < 90:  # OP_RETURN (variable but usually small)
        return token_bytes(randbelow(80) + 1)
    else:  # Other less common types
        return token_bytes(randbelow(35) + 1)  # 1-35 bytes


def get_random_scriptsig(scriptsig_type: str = None):
    """
    Generate a random script_sig with realistic sizes.

    Args:
        scriptsig_type (str, optional): Not used in this simplified version.

    Returns:
        bytes: A randomly sized script_sig
    """
    # Choose a size based on common scriptSig lengths
    r = randbelow(100)
    if r < 60:  # P2PKH (most common, ~106-107 bytes)
        return token_bytes(randbelow(5) + 105)
    elif r < 85:  # P2SH (typically between 23-150 bytes)
        return token_bytes(randbelow(128) + 23)
    elif r < 95:  # Segwit (empty script_sig, 0 bytes)
        return b''
    else:  # Other less common or complex redeem scripts
        return token_bytes(randbelow(400) + 1)  # 1-400 bytes


def get_random_input(scriptsig_bits: int = 16):
    rand_scriptsig_size = randbits(scriptsig_bits)
    return Input(
        txid=token_bytes(32),  # txid | 32 bytes
        vout=randbits(32),  # vout | 4 bytes
        script_sig=get_random_scriptsig(),  # scriptsig | var len
        sequence=randbits(32)  # sequqnce | 4 bytes
    )


def get_random_output(scriptpubkey_bits: int = 1):
    rand_scriptpubkey_sze = randbits(scriptpubkey_bits)
    return Output(
        amount=randbits(63),  # 8 byte integer | Account for SQLITE signed integer storage
        script_pubkey=get_random_scriptpubkey()  # script pubkey | var len
    )


def get_random_witness_item(item_bits: int = 8):
    rand_witnessitem_size = randbits(item_bits)
    return WitnessItem(
        item=token_bytes(rand_witnessitem_size)
    )


def get_random_witness(wit_num: int = 3):
    rand_witnum = randbelow(wit_num) + 1
    return Witness(
        items=[get_random_witness_item() for _ in range(rand_witnum)]
    )


def get_random_tx(input_num: int = 3, output_num: int = 3, is_segwit: bool = True):
    rand_input_num = randbelow(input_num) + 1
    rand_output_num = randbelow(output_num) + 1
    rand_inputs = [get_random_input() for _ in range(rand_input_num)]
    rand_outputs = [get_random_output() for _ in range(rand_output_num)]

    rand_witness = [get_random_witness() for _ in range(rand_input_num)] if is_segwit else []
    rand_locktime = randbits(32)  # 4 byte integer
    rand_version = randbits(32)  # 4 bytes integer

    return Transaction(
        inputs=rand_inputs,
        outputs=rand_outputs,
        witnesses=rand_witness,
        locktime=rand_locktime,
        version=rand_version
    )


def get_random_block(tx_num: int = 3):
    rand_txs = [get_random_tx() for _ in range(tx_num)]
    return Block(
        prev_block=token_bytes(32),
        transactions=rand_txs,
        timestamp=randbits(32),
        bits=token_bytes(4),
        nonce=randbits(32),
        version=randbits(32)
    )


def get_random_block_header(tx_num: int = 3):
    return BlockHeader(
        version=randbits(32),
        prev_block=token_bytes(32),
        merkle_root=token_bytes(32),
        timestamp=randbits(32),
        bits=token_bytes(4),
        nonce=randbits(32)
    )


def get_random_prefilled_tx(index: int = None, is_segwit: bool = True):
    tx = get_random_tx(is_segwit=is_segwit)
    index = randbelow(1000) if index is None else index
    return PrefilledTransaction(tx=tx, index=index)


def get_random_shortid(shortid_bytes: int = 6):
    return token_bytes(shortid_bytes)


def get_random_nonce(nonce_bytes: int = 8):
    return int.from_bytes(token_bytes(nonce_bytes), "little")


def get_random_invtype(with_error: bool = False):
    lower_bound = 0 if not with_error else 1
    rand_num = randint(lower_bound, 7)
    if 5 <= rand_num <= 7:
        rand_num = (1 << 30) + (rand_num - 4)

    return InvType(rand_num)
