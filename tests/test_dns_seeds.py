import socket
import threading

import pytest

from src.config import NetworkName
from src.core import NETWORK
from src.network.dns_seeds import BITCOIN_CORE_SEED_VERSION, DNS_SEEDS, DNSSeedBootstrap
from src.network.peer_address_book import PeerAddressBook, PeerSource
from src.node.node import Node

IPV4_PEER = "192.0.2.10"
SECOND_IPV4_PEER = "198.51.100.20"
IPV6_PEER = "2001:db8::10"
DNS_FAILURE = "DNS unavailable"


def _ipv4_info(host: str, port: int):
    return socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port)


def _ipv6_info(host: str, port: int):
    return socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (host, port, 0, 0)


def test_dns_seed_inventory_matches_supported_bitcoin_core_networks():
    assert BITCOIN_CORE_SEED_VERSION == "v31.0"
    assert DNS_SEEDS[NetworkName.MAINNET] == NETWORK.MAINNET_DNS_SEEDS
    assert DNS_SEEDS[NetworkName.TESTNET] == NETWORK.TESTNET_DNS_SEEDS
    assert DNS_SEEDS[NetworkName.SIGNET] == NETWORK.SIGNET_DNS_SEEDS
    assert DNS_SEEDS[NetworkName.REGTEST] == ()
    assert len(DNS_SEEDS[NetworkName.MAINNET]) == 8
    assert len(DNS_SEEDS[NetworkName.TESTNET]) == 5
    assert len(DNS_SEEDS[NetworkName.SIGNET]) == 2
    assert NETWORK.MAINNET_DNS_SEEDS[0] == "seed.bitcoin.sipa.be."
    assert NETWORK.TESTNET_DNS_SEEDS[0] == "testnet-seed.bitcoin.jonasschnelli.ch."
    assert NETWORK.SIGNET_DNS_SEEDS[0] == "seed.signet.bitcoin.sprovoost.nl."


def test_dns_bootstrap_deduplicates_ipv4_and_ipv6_results_across_seeds():
    address_book = PeerAddressBook(NETWORK.MAINNET_PORT)
    seeds = DNS_SEEDS[NetworkName.MAINNET]

    def resolver(seed, port):
        if seed == seeds[0]:
            return [_ipv4_info(IPV4_PEER, port), _ipv6_info(IPV6_PEER, port)]
        return [_ipv4_info(IPV4_PEER, port), _ipv4_info(SECOND_IPV4_PEER, port)]

    result = DNSSeedBootstrap(NetworkName.MAINNET, address_book, resolver=resolver).resolve()

    assert result.queried_seeds == seeds
    assert result.resolved_count == 3
    assert result.failures == ()
    assert len(address_book) == 3
    assert address_book.get(IPV4_PEER).sources == {PeerSource.DNS_SEED}
    assert address_book.get(IPV6_PEER).sources == {PeerSource.DNS_SEED}


def test_dns_bootstrap_continues_after_an_individual_seed_failure():
    address_book = PeerAddressBook(NETWORK.SIGNET_PORT)
    failed_seed, successful_seed = DNS_SEEDS[NetworkName.SIGNET]

    def resolver(seed, port):
        if seed == failed_seed:
            raise socket.gaierror(DNS_FAILURE)
        return [_ipv4_info(IPV4_PEER, port)]

    result = DNSSeedBootstrap(NetworkName.SIGNET, address_book, resolver=resolver).resolve()

    assert result.queried_seeds == (failed_seed, successful_seed)
    assert result.peer_keys == ((IPV4_PEER, NETWORK.SIGNET_PORT),)
    assert result.failures[0].seed == failed_seed
    assert DNS_FAILURE in result.failures[0].error
    assert address_book.get(IPV4_PEER).port == NETWORK.SIGNET_PORT


def test_dns_bootstrap_queries_seeds_with_bounded_parallelism():
    active_queries = 0
    maximum_queries = 0
    lock = threading.Lock()
    workers = 2
    rendezvous = threading.Barrier(workers)

    def resolver(_seed, port):
        nonlocal active_queries, maximum_queries
        with lock:
            active_queries += 1
            maximum_queries = max(maximum_queries, active_queries)
        try:
            rendezvous.wait(timeout=2)
            return [_ipv4_info(IPV4_PEER, port)]
        finally:
            with lock:
                active_queries -= 1

    result = DNSSeedBootstrap(
        NetworkName.MAINNET,
        PeerAddressBook(NETWORK.MAINNET_PORT),
        resolver=resolver,
        max_workers=workers,
    ).resolve()

    assert result.queried_seeds == DNS_SEEDS[NetworkName.MAINNET]
    assert result.resolved_count == 1
    assert maximum_queries == workers


@pytest.mark.parametrize("max_workers", [0, -1, True])
def test_dns_bootstrap_rejects_invalid_worker_count(max_workers):
    with pytest.raises(ValueError, match="positive integer"):
        DNSSeedBootstrap(
            NetworkName.MAINNET,
            PeerAddressBook(NETWORK.MAINNET_PORT),
            max_workers=max_workers,
        )


def test_regtest_has_no_dns_bootstrap_queries():
    calls = []

    def resolver(seed, port):
        calls.append((seed, port))
        return []

    result = DNSSeedBootstrap(
        NetworkName.REGTEST,
        PeerAddressBook(NETWORK.REGTEST_PORT),
        resolver=resolver,
    ).resolve()

    assert calls == []
    assert result.queried_seeds == ()
    assert result.resolved_count == 0


def test_node_bootstrap_dns_uses_configured_network_and_shared_address_book(tmp_path):
    node = Node(db_path=tmp_path / "node.db", network=NetworkName.TESTNET)

    try:
        result = node.bootstrap_dns(
            resolver=lambda _seed, port: [_ipv4_info(IPV4_PEER, port)]
        )

        assert result.network is NetworkName.TESTNET
        assert result.port == NETWORK.TESTNET_PORT
        assert result.resolved_count == 1
        assert node.address_book.get(IPV4_PEER, NETWORK.TESTNET_PORT) is not None
    finally:
        node.close()
