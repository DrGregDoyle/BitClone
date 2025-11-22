import ipaddress
from io import BytesIO

import pytest

from src.backup.data import normalize, to_display, pack16, read_ip16, write_ip16


# ---------- IPv4-mapped behavior ----------

@pytest.mark.parametrize("v4", ["1.2.3.4", "192.168.0.1", "255.255.255.255"])
def test_ipv4_string_normalizes_to_v6_mapped_and_displays_v4(v4):
    ip6 = normalize(v4)
    assert isinstance(ip6, ipaddress.IPv6Address)
    assert ip6.ipv4_mapped == ipaddress.IPv4Address(v4)
    assert to_display(ip6) == v4
    # wire is always 16 bytes
    assert len(pack16(ip6)) == 16


@pytest.mark.parametrize("text", [
    "::ffff:1.2.3.4",
    "[::ffff:1.2.3.4]",  # bracketed form
    " ::ffff:192.168.0.1 ",  # whitespace
])
def test_ipv6_text_that_is_v4_mapped_displays_as_v4(text):
    ip6 = normalize(text)
    assert to_display(ip6) == str(ip6.ipv4_mapped)


def test_ipv4_bytes_normalize_and_display():
    v4 = ipaddress.IPv4Address("10.0.0.7")
    ip6 = normalize(v4.packed)  # 4-byte input
    assert ip6.ipv4_mapped == v4
    assert to_display(ip6) == "10.0.0.7"


def test_ipv4_mapped_bytes_roundtrip():
    v4 = ipaddress.IPv4Address("8.8.8.8")
    ip6 = normalize(v4.packed)
    b = pack16(ip6)
    assert len(b) == 16
    # back to IPv6Address via read_ip16
    ip6b = read_ip16(BytesIO(b))
    assert ip6b == ip6
    assert to_display(ip6b) == "8.8.8.8"


# ---------- Zone (scope) index handling ----------

@pytest.mark.parametrize("text,expected", [
    ("fe80::1%eth0", "fe80::1"),  # interface name (Unix)
    ("fe80::1%3", "fe80::1"),  # numeric index (Windows)
    ("[fe80::1%25en0]", "fe80::1"),  # percent-encoded in URIs
    ("  [fe80::1]  ", "fe80::1"),  # bracketed, whitespace
])
def test_zone_index_is_stripped(text, expected):
    ip6 = normalize(text)
    assert isinstance(ip6, ipaddress.IPv6Address)
    assert str(ip6) == expected
    assert to_display(ip6) == expected
    assert pack16(ip6) == ipaddress.IPv6Address(expected).packed


# ---------- Plain IPv6 behavior ----------

@pytest.mark.parametrize("text", ["2001:db8::1", "::1", "2001:0db8:0000::0001"])
def test_plain_ipv6_preserved_and_displayed_as_ipv6(text):
    ip6 = normalize(text)
    assert isinstance(ip6, ipaddress.IPv6Address)
    assert ip6.ipv4_mapped is None
    assert to_display(ip6) == str(ip6)  # compressed form from ipaddress
    assert len(pack16(ip6)) == 16


# ---------- Stream read/write ----------

def test_read_ip16_and_write_ip16_roundtrip():
    ip6 = normalize("2001:db8::dead:beef")
    data = write_ip16(ip6)
    assert len(data) == 16
    ip6b = read_ip16(BytesIO(data))
    assert ip6b == ip6


# ---------- Errors / edge cases ----------

@pytest.mark.parametrize("bad", [b"", b"\x00" * 4 + b"\x01", b"\x00" * 15])  # wrong lengths
def test_read_ip16_raises_on_short_reads(bad):
    with pytest.raises(ValueError):
        _ = read_ip16(BytesIO(bad))


@pytest.mark.parametrize("bad", ["not-an-ip", "999.999.999.999", ":::1", "[::1"])
def test_normalize_raises_on_invalid_strings(bad):
    with pytest.raises(ValueError):
        _ = normalize(bad)


def test_normalize_rejects_weird_bytes_length():
    with pytest.raises(ValueError):
        _ = normalize(b"\x01\x02\x03")  # neither 4 nor 16
