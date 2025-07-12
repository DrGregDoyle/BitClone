"""
Tests for the data structures created in BIP-0152
"""
import json
from random import randint

from src.logger import get_logger
from src.network_utils import *
from tests.randbtc_generators import get_random_prefilled_tx, get_random_block_header, get_random_nonce, \
    get_random_shortid

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
    # Verify differential encoding
    prefilled_tx2.differentially_encode_index(previous_index=prefilled_tx1.index)
    assert prefilled_tx2.index == 0, "Failed to differentially encode index for squential indices"


def test_header_and_short_ids():
    random_header = get_random_block_header()
    random_nonce = get_random_nonce()
    random_shortids_length = randint(4, 8)
    random_prefilled_tx_length = randint(3, 5)
    random_shortids = [get_random_shortid() for _ in range(random_shortids_length)]
    random_prefilled_tx = [get_random_prefilled_tx(index=n) for n in range(random_prefilled_tx_length)]

    random_header_and_shortid = HeaderAndShortIDs(random_header, random_nonce, random_shortids, random_prefilled_tx)
    # logger.info(f"RANDOM HEADER AND SHORTID: {random_header_and_shortid.to_json()}")
    # print(f"RANDOM HEADER AND SHORTID: {random_header_and_shortid.to_json()}")
    ugly_json = random_header_and_shortid.to_json()
    print(json.dumps(json.loads(ugly_json), indent=2))
    # recovered_header_and_shortid = HeaderAndShortIDs.from_bytes(random_header_and_shortid.to_bytes())
    # logger.info(f"RECOVERED HEADER AND SHORTID: {recovered_header_and_shortid.to_json()}")

    # # Verify to_bytes -> from_bytes
    # assert recovered_header_and_shortid.to_bytes() == random_header_and_shortid.to_bytes(), \
    #     "to_bytes -> from_bytes construction failed for HeaderAndShortIDs"
