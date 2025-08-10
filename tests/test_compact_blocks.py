"""
Tests for the data structures created in BIP-0152
"""
from random import randint
from secrets import token_bytes

from src.block import HeaderAndShortIDs, BlockTransactionsRequest, BlockTransactions
from src.crypto import hash256
from src.data.varint import write_compact_size
from src.logger import get_logger
from src.tx import PrefilledTransaction
from tests.randbtc_generators import get_random_prefilled_tx, get_random_block_header, get_random_nonce, \
    get_random_shortid, get_random_tx

logger = get_logger(__name__)


def test_prefilled_tx():
    prefilled_tx1 = get_random_prefilled_tx()
    prefilled_tx2 = get_random_prefilled_tx(index=prefilled_tx1.index + 1)

    recovered_ptx1 = PrefilledTransaction.from_bytes(prefilled_tx1.to_bytes())
    recovered_ptx2 = PrefilledTransaction.from_bytes(prefilled_tx2.to_bytes())

    # Verify to_bytes -> from_bytes
    assert prefilled_tx1.to_bytes() == recovered_ptx1.to_bytes(), "to_bytes -> from_bytes construction failed for " \
                                                                  "PrefilledTransaction1"
    assert prefilled_tx2.to_bytes() == recovered_ptx2.to_bytes(), "to_bytes -> from_bytes construction failed for " \
                                                                  "PrefilledTransaction2"


def test_header_and_short_ids():
    random_header = get_random_block_header()
    random_nonce = get_random_nonce()
    random_shortids_length = randint(4, 8)
    random_prefilled_tx_length = randint(3, 5)
    random_shortids = [get_random_shortid() for _ in range(random_shortids_length)]
    random_prefilled_tx = [get_random_prefilled_tx(index=n) for n in range(random_prefilled_tx_length)]

    random_header_and_shortid = HeaderAndShortIDs(random_header, random_nonce, random_shortids, random_prefilled_tx)
    recovered_header_and_shortid = HeaderAndShortIDs.from_bytes(random_header_and_shortid.to_bytes())

    # Verify to_bytes -> from_bytes
    assert recovered_header_and_shortid.to_bytes() == random_header_and_shortid.to_bytes(), \
        "to_bytes -> from_bytes construction failed for HeaderAndShortIDs"


def test_block_tx_request():
    random_hash = hash256(token_bytes(8))
    random_index = int.from_bytes(token_bytes(2), "big")
    # 3 consecutive differentially encoded indexes
    test_diff_list = [write_compact_size(random_index), write_compact_size(0), write_compact_size(0)]
    random_block_tx_request = BlockTransactionsRequest(random_hash, test_diff_list)
    recovered_block_tx_req = BlockTransactionsRequest.from_bytes(random_block_tx_request.to_bytes())

    # Verify to_bytes -> from_bytes
    assert recovered_block_tx_req.to_bytes() == random_block_tx_request.to_bytes(), \
        "to_bytes -> from_bytes construction failed for BlockTransactionRequest"


def test_block_transactions():
    random_hash = hash256(token_bytes(8))
    random_tx_num = randint(3, 5)
    tx_list = []
    for _ in range(random_tx_num):
        tx_list.append(get_random_tx())

    random_block_tx = BlockTransactions(random_hash, tx_list)
    recovered_block_tx = BlockTransactions.from_bytes(random_block_tx.to_bytes())

    print(f"RANDOM BLOCK TRANSACTION: {random_block_tx.to_json()}")

    # Verify to_bytes -> from_bytes
    assert random_block_tx.to_bytes() == recovered_block_tx.to_bytes(), \
        "to_bytes -> from_bytes construction failed for BlockTransactions"
