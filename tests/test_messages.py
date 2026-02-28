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
    addr_list = [getrand_netaddr(is_version=False) for _ in range(rand_addr_num)]
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
    random_remote_addr = getrand_netaddr(is_version=True)
    random_local_addr = getrand_netaddr(is_version=True)
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
