"""
Tests for Various message classes
"""
from random import randint, choice
from secrets import token_bytes
from string import ascii_letters

import pytest

from src.network.datatypes.network_types import *
from src.network.messages.ctrl_msg import *
from src.network.messages.data_msg import *
from src.network.messages.message import EmptyMessage


@pytest.mark.parametrize("msg_class, expected_command", [
    (FilterClear, "filterclear"),
    (SendHeaders, "sendheaders"),
    (VerAck, "verack"),
    (MemPool, "mempool"),
    (GetAddr, 'getaddr')
])
def test_empty_messages(msg_class, expected_command):
    """
    We verify all Message classes which inherit from EmptyMessage are as expected based on their commands
    """
    default_empty_msg = EmptyMessage()
    msg = msg_class()

    assert msg.header.checksum == default_empty_msg.header.checksum, f"{msg_class.__name__} emptymessage checksum failed"
    assert msg.header.command == expected_command, f"{msg_class.__name__} emptymessage command failed"
    assert msg.header.size == 0, f"{msg_class.__name__} size value failed"
    assert msg.header.magic_bytes == default_empty_msg.header.magic_bytes, f"{msg_class.__name__} magic bytes failed"


def test_ping_pong():
    """
    We test the Ping and Pong message classes.
    """
    random_nonce = int.from_bytes(token_bytes(8), "big")
    test_ping_msg = Ping(random_nonce)
    test_pong_msg = Pong(random_nonce)

    # Commands should differ
    assert test_ping_msg.header.command == "ping"
    assert test_pong_msg.header.command == "pong"

    # Everything else should match
    assert test_ping_msg.header.checksum == test_pong_msg.header.checksum, "Ping/Pong checksum mismatch"
    assert test_ping_msg.header.size == test_pong_msg.header.size, "Ping/Pong size mismatch"
    assert test_ping_msg.header.magic_bytes == test_pong_msg.header.magic_bytes, "Ping/Pong magic_bytes mismatch"
    assert test_ping_msg.payload == test_pong_msg.payload, "Ping/Pong payload mismatch"


# --- Serialization -> Deserialization loops --- #

def test_addr(getrand_netaddr):
    rand_addr_num = randint(3, 5)
    addr_list = [getrand_netaddr() for _ in range(rand_addr_num)]
    addr_msg = Addr(addr_list)
    constructed_msg = Addr.from_bytes(addr_msg.to_bytes())
    assert constructed_msg == addr_msg, "Addr message failed to_bytes -> from_bytes construction"
    payload_msg = Addr.from_payload(addr_msg.to_payload())
    assert payload_msg == addr_msg, "Addr message failed to_payload -> from_payload construction"


def test_feefilter():
    rand_feerate = int.from_bytes(token_bytes(8), "big")
    feefilter_msg = FeeFilter(rand_feerate)
    constructed_feefilter = FeeFilter.from_bytes(feefilter_msg.to_bytes())
    assert constructed_feefilter == feefilter_msg, "FeeFilter message failed to_bytes -> from_bytes construction"
    payload_feefilter = FeeFilter.from_payload(feefilter_msg.to_payload())
    assert payload_feefilter == feefilter_msg, "FeeFilter message failed to_payload -> from_payload construction"


def test_filteradd():
    random_element = token_bytes(randint(8, 520))
    filteradd_msg = FilterAdd(random_element)
    constructed_filteradd = FilterAdd.from_bytes(filteradd_msg.to_bytes())
    assert constructed_filteradd == filteradd_msg, "FilterAdd message failed to_bytes -> from_bytes construction"
    payload_filteradd = FilterAdd.from_payload(filteradd_msg.to_payload())
    assert payload_filteradd == filteradd_msg, "FilterAdd message failed to_payload -> from_payload construction"


def test_filterload():
    # --- Construct Message
    random_bitfilter = token_bytes(randint(8, 36_000))
    random_hashnum = randint(1, 50)
    random_tweak = int.from_bytes(token_bytes(4), "big")
    random_nflags = choice(list(BloomFlags))
    filterload_msg = FilterLoad(random_bitfilter, random_hashnum, random_tweak, random_nflags)

    # --- Message and Payload bytes
    filter_load_bytes = filterload_msg.to_bytes()
    filter_load_payload = filterload_msg.payload

    # --- Reconstruction
    from_bytes_filterload = FilterLoad.from_bytes(filter_load_bytes)
    from_payload_filterload = FilterLoad.from_payload(filter_load_payload)

    # --- Asserts
    assert from_bytes_filterload == filterload_msg, "FilterLoad message failed to_bytes -> from_bytes construction"
    assert from_payload_filterload == filterload_msg, "FilterLoad message failed to_payload -> from_payload construction"


@pytest.mark.parametrize("message_type, valid_types, has_extra_data", [
    ("tx", [RejectType(0x01), RejectType(0x10), RejectType(0x12), RejectType(0x40), RejectType(0x41), RejectType(0x42)],
     True),
    ("block", [RejectType(0x01), RejectType(0x10), RejectType(0x11), RejectType(0x43)], True),
    ("version", [RejectType(0x01), RejectType(0x11), RejectType(0x12)], False),
])
def test_reject(message_type, valid_types, has_extra_data):
    random_type = choice(valid_types)
    random_reason = "rejected-" + "".join(choice(ascii_letters) for _ in range(randint(10, 20)))
    random_data = token_bytes(32) if has_extra_data else b""
    reject_msg = Reject(message_type, random_type, random_reason, random_data)

    reject_msg_bytes = reject_msg.to_bytes()
    reject_msg_payload = reject_msg.payload

    from_bytes_reject = Reject.from_bytes(reject_msg_bytes)
    from_payload_reject = Reject.from_payload(reject_msg_payload)

    assert from_payload_reject == reject_msg, f"Reject '{message_type}' failed to_payload -> from_payload construction"
    assert from_bytes_reject == reject_msg, f"Reject '{message_type}' failed to_bytes -> from_bytes construction"


def test_version(getrand_netaddr):
    # --- Construction
    random_version = randint(1, 70015)
    random_services = choice(list(Services))
    random_timestamp = int.from_bytes(token_bytes(8), "big")
    random_remote_addr = getrand_netaddr()
    random_local_addr = getrand_netaddr()
    random_nonce = int.from_bytes(token_bytes(8), "big")
    random_user_agent = "/" + "".join(choice(ascii_letters) for _ in range(randint(5, 15))) + "/"
    random_last_block = randint(0, 800_000)
    version_msg = Version(random_version, random_services, random_timestamp, random_remote_addr,
                          random_local_addr, random_nonce, random_user_agent, random_last_block)

    # --- Message and payload bytes
    version_msg_bytes = version_msg.to_bytes()
    version_msg_payload = version_msg.payload

    # --- Reconstruction
    from_bytes_version = Version.from_bytes(version_msg_bytes)
    from_payload_version = Version.from_payload(version_msg_payload)

    # --- Asserts
    assert from_bytes_version == version_msg, "Version message failed to_bytes -> from_bytes construction"
    assert from_payload_version == version_msg, "Version message failed to_payload -> from_payload construction"


def test_blockmsg(getrand_block):
    # --- Construction
    random_block = getrand_block()
    block_msg = BlockMessage(random_block)

    # --- Message and payload bytes
    block_msg_bytes = block_msg.to_bytes()
    block_payload_bytes = block_msg.payload

    # -- Reconstruction
    from_bytes_blockmsg = BlockMessage.from_bytes(block_msg_bytes)
    from_payload_blockmsg = BlockMessage.from_payload(block_payload_bytes)

    # --- Asserts
    assert from_bytes_blockmsg == block_msg, "Block message failed to_bytes -> from_bytes construction"
    assert from_payload_blockmsg == block_msg, "Block message failed to_payload -> from_payload construction"


def test_blocktxns(getrand_blocktxns):
    random_blocktxns = getrand_blocktxns()
    block_txns_msg = BlockTxn(random_blocktxns)

    # --- Message and payload bytes
    blocktxns_msg_bytes = block_txns_msg.to_bytes()
    blocktxns_payload_bytes = block_txns_msg.payload

    # -- Reconstruction
    from_bytes_blocktxnsmsg = BlockTxn.from_bytes(blocktxns_msg_bytes)
    from_payload_blocktxnsmsg = BlockTxn.from_payload(blocktxns_payload_bytes)

    # --- Asserts
    assert from_bytes_blocktxnsmsg == block_txns_msg, "BlockTxns message failed to_bytes -> from_bytes construction"
    assert from_payload_blocktxnsmsg == block_txns_msg, ("BlockTxns message failed to_payload -> from_payload "
                                                         "construction")


def test_cmpctblock_msg(getrand_headerandshortids):
    """Test the CmpctBlock Message"""
    rand_hashids = getrand_headerandshortids()
    cmpctblock_msg = CmpctBlock(rand_hashids)

    # --- Message and payload bytes
    cmpctblock_msg_bytes = cmpctblock_msg.to_bytes()
    cmpctblock_payload_bytes = cmpctblock_msg.to_payload()

    # --- Reconstruction
    from_bytes_cmpctblock = CmpctBlock.from_bytes(cmpctblock_msg_bytes)
    from_payload_cmpctblock = CmpctBlock.from_payload(cmpctblock_payload_bytes)

    # --- Asserts
    assert from_bytes_cmpctblock == cmpctblock_msg, "CmpctBlock failed to_bytes -> from_bytes construction"
    assert from_payload_cmpctblock == cmpctblock_msg, (
        "CmpctBlock message failed to_payload ->  from_payload construction")


def test_getblocktxn(getrand_blocktxnrqst):
    random_blocktxnrqst = getrand_blocktxnrqst()
    getblocktxn_msg = GetBlockTxn(random_blocktxnrqst)

    # --- Message and payload bytes
    getblocktxn_bytes = getblocktxn_msg.to_bytes()
    getblocktxn_payload = getblocktxn_msg.payload

    # --- Reconstruction
    from_bytes_getblocktxn = GetBlockTxn.from_bytes(getblocktxn_bytes)
    from_payload_getblocktxn = GetBlockTxn.from_payload(getblocktxn_payload)

    # --- Asserts
    assert from_bytes_getblocktxn == getblocktxn_msg, "GetBlockTxn message failed to_bytes -> from_bytes construction"
    assert from_payload_getblocktxn == getblocktxn_msg, "GetBlockTxn message failed to_payload -> from_payload construction"


def test_getblocks(getrand_getblocks):
    getblocks_msg = getrand_getblocks()

    getblocks_bytes = getblocks_msg.to_bytes()
    getblocks_payload = getblocks_msg.payload

    from_bytes_getblocks = GetBlocks.from_bytes(getblocks_bytes)
    from_payload_getblocks = GetBlocks.from_payload(getblocks_payload)

    assert from_bytes_getblocks == getblocks_msg, "GetBlocks message failed to_bytes -> from_bytes construction"
    assert from_payload_getblocks == getblocks_msg, "GetBlocks message failed to_payload -> from_payload construction"


def test_getdata(getrand_getdata):
    # --- Construction
    getdata_msg = getrand_getdata()

    # --- Bytes and Payload
    getdata_bytes = getdata_msg.to_bytes()
    getdata_payload = getdata_msg.payload

    # --- Reconstruction
    from_bytes_getdata = GetData.from_bytes(getdata_bytes)
    from_payload_getdata = GetData.from_payload(getdata_payload)

    # --- Asserts
    assert from_bytes_getdata == getdata_msg, "GetData message failed to_bytes -> from_bytes construction"
    assert from_payload_getdata == getdata_msg, "GetData message failed to_payload -> from_payload construction"


def test_getheaders(getrand_getheaders):
    # --- Construction
    getheaders_msg = getrand_getheaders()

    # --- Payload and Bytes
    getheaders_bytes = getheaders_msg.to_bytes()
    getheaders_payload = getheaders_msg.payload

    # --- Reconstruction
    from_bytes_getheaders = GetHeaders.from_bytes(getheaders_bytes)
    from_payload_getheaders = GetHeaders.from_payload(getheaders_payload)

    # --- Asserts
    assert from_bytes_getheaders == getheaders_msg, "GetHeaders message failed to_bytes -> from_bytes construction"
    assert from_payload_getheaders == getheaders_msg, "GetHeaders message failed to_payload -> from_payload construction"


def test_headers(getrand_headers):
    # --- Construction
    headers_msg = getrand_headers()

    # --- Bytes and Payload
    headers_bytes = headers_msg.to_bytes()
    headers_payload = headers_msg.payload

    # --- Reconstruction
    from_bytes_headers = Headers.from_bytes(headers_bytes)
    from_payload_headers = Headers.from_payload(headers_payload)

    # --- Asserts
    assert from_bytes_headers == headers_msg, "Headers message failed to_bytes -> from_bytes construction"
    assert from_payload_headers == headers_msg, "Headers message failed to_payload -> from_payload construction"


def test_inv(getrand_inv):
    # --- Construction
    inv_msg = getrand_inv()

    # --- Bytes and Payload
    inv_bytes = inv_msg.to_bytes()
    inv_payload = inv_msg.payload

    # --- Reconstruction
    from_bytes_inv = Inv.from_bytes(inv_bytes)
    from_payload_inv = Inv.from_payload(inv_payload)

    # --- Asserts
    assert from_bytes_inv == inv_msg, "Inv message failed to_bytes -> from_bytes construction"
    assert from_payload_inv == inv_msg, "Inv message failed to_payload -> from_payload construction"


def test_notfound(getrand_notfound):
    # --- Construction
    notfound_msg = getrand_notfound()

    # --- Bytes and Payload
    notfound_bytes = notfound_msg.to_bytes()
    notfound_payload = notfound_msg.payload

    # --- Reconstruction
    from_bytes_notfound = NotFound.from_bytes(notfound_bytes)
    from_payload_notfound = NotFound.from_payload(notfound_payload)

    # --- Asserts
    assert from_bytes_notfound == notfound_msg, "NotFound message failed to_bytes -> from_bytes construction"
    assert from_payload_notfound == notfound_msg, "NotFound message failed to_payload -> from_payload construction"


def test_merkleblock(getrand_merkleblock):
    # --- Construction
    merkleblock_msg = getrand_merkleblock()

    # --- Bytes and Payload
    merkleblock_bytes = merkleblock_msg.to_bytes()
    merkleblock_payload = merkleblock_msg.payload

    # --- Reconstruction
    from_bytes_merkleblock = MerkleBlock.from_bytes(merkleblock_bytes)
    from_payload_merkleblock = MerkleBlock.from_payload(merkleblock_payload)

    # --- Asserts
    assert from_bytes_merkleblock == merkleblock_msg, "MerkleBlock message failed to_bytes -> from_bytes construction"
    assert from_payload_merkleblock == merkleblock_msg, (
        "MerkleBlock message failed to_payload -> from_payload construction")


@pytest.mark.parametrize("announce, version", [
    (True, 1),
    (False, 1),
    (True, 2),
])
def test_sendcmpct(announce, version):
    # --- Construction
    sendcmpct_msg = SendCmpct(announce, version)

    # --- Bytes and Payload
    sendcmpct_bytes = sendcmpct_msg.to_bytes()
    sendcmpct_payload = sendcmpct_msg.payload

    # --- Reconstruction
    from_bytes_sendcmpct = SendCmpct.from_bytes(sendcmpct_bytes)
    from_payload_sendcmpct = SendCmpct.from_payload(sendcmpct_payload)

    # --- Asserts
    assert from_bytes_sendcmpct == sendcmpct_msg, "SendCmpct message failed to_bytes -> from_bytes construction"
    assert from_payload_sendcmpct == sendcmpct_msg, "SendCmpct message failed to_payload -> from_payload construction"
    assert from_bytes_sendcmpct.announce == announce, "SendCmpct announce field mismatch"
    assert from_bytes_sendcmpct.version == version, "SendCmpct version field mismatch"


def test_txmessage(getrand_tx):
    # --- Construction
    random_tx = getrand_tx()
    tx_msg = Txn(random_tx)

    # --- Bytes and Payload
    tx_msg_bytes = tx_msg.to_bytes()
    tx_msg_payload = tx_msg.payload

    # --- Reconstruction
    from_bytes_txmsg = Txn.from_bytes(tx_msg_bytes)
    from_payload_txmsg = Txn.from_payload(tx_msg_payload)

    # --- Asserts
    assert from_bytes_txmsg == tx_msg, "TxMessage failed to_bytes -> from_bytes construction"
    assert from_payload_txmsg == tx_msg, "TxMessage failed to_payload -> from_payload construction"
