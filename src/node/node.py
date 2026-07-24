"""
The Node class - main runtime coordinator for BitClone.
"""
from __future__ import annotations

import random
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.config import BitCloneConfig, NetworkName
from src.core import BLOCK, NETWORK, TX, NetworkError, get_logger
from src.mempool.mempool import MemPool
from src.database.bitcoin_core_rpc import BitcoinCoreRPC
from src.mining.miner import Miner
from src.network.datatypes.network_data import InvVector, NetAddr
from src.network.datatypes.network_types import InvType, PeerState, Services
from src.network.dns_seeds import (
    DEFAULT_DNS_SEED_WORKERS,
    DNSResolver,
    DNSSeedBootstrap,
    DNSSeedResult,
)
from src.network.messages.ctrl_msg import Addr, GetAddr, SendAddrV2, VerAck, Version, WtxidRelay
from src.network.messages.data_msg import BlockMessage, GetData, GetHeaders, Headers, Inv, NotFound, Txn
from src.network.messages.message import Message
from src.network.header_sync import HeaderSync, HeaderSyncState
from src.network.inventory import InflightInventory, inventory_key
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddress, PeerAddressBook, PeerKey, PeerSource
from src.network.peer_manager import PeerManager
from src.network.transport import Transport
from src.tx.tx import Tx, TxIn, TxOut
from src.wallet.wallet import Wallet

logger = get_logger(__name__)


class Node:
    """
    Coordinates blockchain, mempool, mining, wallet, and networking components.

    Consensus and policy rules stay in their component modules. Node owns their
    lifecycle and provides a stable API for the future CLI/RPC layer.
    """

    ADDR_RELAY_PEER_COUNT = 2

    def __init__(
            self,
            db_path: str | Path | None = None,
            data_dir: str | Path | None = None,
            network: str | NetworkName = NetworkName.MAINNET,
            config: BitCloneConfig | None = None,
            blockchain: Blockchain | None = None,
            mempool: MemPool | None = None,
            wallet: Wallet | None = None,
            miner: Miner | None = None,
            transport: Transport | None = None,
            address_book: PeerAddressBook | None = None,
            peer_manager: PeerManager | None = None,
            target_outbound: int = 8,
            inventory_requests: InflightInventory | None = None,
            header_sync: HeaderSync | None = None,
            core_rpc: BitcoinCoreRPC | None = None,
    ):
        self.config = config or BitCloneConfig.from_options(
            data_dir=data_dir,
            network=network,
            db_path=db_path,
        )
        self.db_path = self.config.db_path
        if core_rpc is None and self.config.block_storage.value == "bitcoin-core-remote":
            core_rpc = BitcoinCoreRPC(
                url=self.config.core_rpc_url,
                username=self.config.core_rpc_user,
                password=self.config.core_rpc_password,
                cookie_file=self.config.core_rpc_cookie,
                timeout=self.config.core_rpc_timeout,
            )
        self.core_rpc = core_rpc

        self.blockchain = blockchain or Blockchain(
            db_path=self.db_path,
            blocks_dir=self.config.blocks_dir,
            storage_mode=self.config.block_storage.value,
            prune_keep_blocks=self.config.prune_keep_blocks,
            core_rpc=self.core_rpc,
        )
        chain_db_path = getattr(self.blockchain.db, "db_path", self.db_path)
        chain_storage_mode = getattr(
            self.blockchain.db,
            "storage_mode",
            self.config.block_storage.value,
        )
        chain_prune_keep_blocks = getattr(
            self.blockchain.db,
            "prune_keep_blocks",
            self.config.prune_keep_blocks,
        )
        if self.core_rpc is None:
            self.core_rpc = getattr(getattr(self.blockchain.db, "block_store", None), "rpc", None)
        self.mempool = mempool or MemPool(
            db_path=chain_db_path,
            blocks_dir=self.config.blocks_dir,
            storage_mode=chain_storage_mode,
            prune_keep_blocks=chain_prune_keep_blocks,
            core_rpc=self.core_rpc,
        )
        self.wallet = wallet
        self.miner = miner or Miner()
        self.transport = transport or Transport(magic_bytes=self.config.magic_bytes)
        self.address_book = address_book if address_book is not None else PeerAddressBook(self.config.p2p_port)
        self._ready_peers: dict[PeerKey, Peer] = {}
        self._ready_peers_lock = threading.RLock()
        self.peer_manager = peer_manager or PeerManager(
            address_book=self.address_book,
            connect_peer=self._connect_address_book_peer,
            ready_peers=lambda: self.ready_peers,
            bootstrap_peers=self.bootstrap_dns,
            target_outbound=target_outbound,
        )
        self.inventory_requests = inventory_requests if inventory_requests is not None else InflightInventory()
        self.header_sync = header_sync or HeaderSync(
            self.blockchain,
            lambda peer, message: self.transport.send(peer, message),
        )
        self.started = False

    # --- Lifecycle ----------------------------------------------------- #

    def start(self) -> None:
        """
        Mark the node runtime as started.

        Networking and background sync loops will be attached here once those
        components exist.
        """
        if self.started:
            return
        self.started = True
        self.peer_manager.start()

    def stop(self) -> None:
        """
        Stop active background work without closing persistent resources.
        """
        self.peer_manager.stop()
        self.stop_mining()
        for peer in self.ready_peers:
            self.disconnect_peer(peer)
        self.started = False

    def close(self) -> None:
        """
        Stop work and close resources owned by downstream components.
        """
        self.stop()
        self.mempool.close()
        self.blockchain.close()

    def shutdown(self) -> None:
        """
        Alias for close(), for CLI/RPC lifecycle readability.
        """
        self.close()

    # --- Peer networking ---------------------------------------------- #

    def bootstrap_dns(
            self,
            resolver: DNSResolver | None = None,
            max_workers: int = DEFAULT_DNS_SEED_WORKERS,
    ) -> DNSSeedResult:
        """Resolve this network's DNS seeds into the shared peer address book."""
        return DNSSeedBootstrap(
            network=self.config.network,
            address_book=self.address_book,
            port=self.config.p2p_port,
            resolver=resolver,
            max_workers=max_workers,
        ).resolve()

    def connect_peer(
            self,
            host: str,
            port: int | None = None,
            source: PeerSource = PeerSource.MANUAL,
    ) -> Peer:
        """Connect to a fixed peer and initiate the Bitcoin version handshake."""
        peer = Peer(host, self.config.p2p_port if port is None else port)
        self.address_book.add_peer(peer, source=source)
        try:
            self.transport.connect(peer)
        except Exception:
            self.address_book.record_failure(peer, source=source, failed_at=time.time())
            raise
        peer.transition(PeerState.HANDSHAKING)

        try:
            local_host, local_port = self.transport.get_local_address(peer)
            peer.local_nonce = secrets.randbits(64)
            version = Version(
                version=NETWORK.PROTOCOL_VERSION,
                services=Services.UNNAMED,
                timestamp=int(time.time()),
                remote_addr=NetAddr(peer.host, peer.port, Services.UNNAMED),
                local_addr=NetAddr(local_host, local_port, Services.UNNAMED),
                nonce=peer.local_nonce,
                user_agent=NETWORK.USER_AGENT,
                last_block=self.blockchain.height,
            )
            self.transport.send(peer, version)
            peer_version = self.transport.recv_one(peer, expected_command=Version.COMMAND)
            if not isinstance(peer_version, Version):
                raise NetworkError(f"Expected Version, received {type(peer_version).__name__}")

            peer.protocol_version = peer_version.protocol_version
            peer.services = peer_version.services
            peer.user_agent = peer_version.user_agent
            peer.nonce = peer_version.nonce
            peer.last_block = peer_version.last_block
            if peer.protocol_version < NETWORK.MIN_PROTOCOL_VERSION:
                raise NetworkError(
                    f"Peer protocol version {peer.protocol_version} is below minimum supported version "
                    f"{NETWORK.MIN_PROTOCOL_VERSION}"
                )

            self.transport.send(peer, VerAck())
            for _ in range(NETWORK.MAX_PRE_VERACK_MESSAGES + 1):
                response = self.transport.recv_one(peer)
                if isinstance(response, VerAck):
                    peer.transition(PeerState.READY)
                    break
                if not isinstance(response, (SendAddrV2, WtxidRelay)):
                    response_command = getattr(response, "command", response.__class__.COMMAND)
                    raise NetworkError(f"Unexpected command before verack: {response_command!r}")
            else:
                raise NetworkError(
                    f"Peer exceeded limit of {NETWORK.MAX_PRE_VERACK_MESSAGES} messages before verack"
                )
            self.transport.send(peer, GetAddr())
        except Exception:
            self.address_book.record_failure(peer, source=source, failed_at=time.time())
            self.transport.disconnect(peer)
            raise

        self.address_book.record_success(peer, source=source, succeeded_at=time.time())
        with self._ready_peers_lock:
            self._ready_peers[peer.key] = peer
        return peer

    def connect_upstream(self, start_header_sync: bool = True) -> Peer:
        """Connect to the configured preferred peer and optionally start header sync."""
        if self.config.upstream_host is None:
            raise ValueError("No preferred upstream host is configured")
        peer = self.connect_peer(
            self.config.upstream_host,
            self.config.configured_upstream_port,
            source=PeerSource.MANUAL,
        )
        if start_header_sync:
            self.start_header_sync(peer)
        return peer

    def _connect_address_book_peer(self, host: str, port: int) -> Peer:
        return self.connect_peer(host, port, source=self._source_for_peer(host, port))

    def _source_for_peer(self, host: str, port: int) -> PeerSource:
        address = self.address_book.get(host, port)
        if address is None or not address.sources:
            return PeerSource.MANUAL
        return min(address.sources, key=lambda item: item.value)

    @property
    def ready_peers(self) -> tuple[Peer, ...]:
        """Return a stable snapshot of peers ready for application messages."""
        with self._ready_peers_lock:
            return tuple(self._ready_peers[key] for key in sorted(self._ready_peers))

    def disconnect_peer(self, peer: Peer) -> None:
        """Disconnect a peer and remove it from the ready-peer registry."""
        with self._ready_peers_lock:
            self._ready_peers.pop(peer.key, None)
        self.inventory_requests.release_peer(peer.key)
        self.header_sync.peer_disconnected(peer)
        self.transport.disconnect(peer)
        self.peer_manager.wake()

    def start_header_sync(self, peer: Peer) -> GetHeaders:
        """Begin or resume header-first synchronization with a ready peer."""
        if not self._is_ready_peer(peer):
            raise ConnectionError(f"Peer {peer.host}:{peer.port} is not ready")
        return self.header_sync.start(peer)

    def sync_headers(self, peer: Peer) -> int:
        """Synchronously receive messages until header-first synchronization completes."""
        if self.header_sync.state is not HeaderSyncState.SYNCING or self.header_sync.peer_key != peer.key:
            self.start_header_sync(peer)
        while self.header_sync.state is HeaderSyncState.SYNCING:
            self.receive_peer_message(peer)
        return self.header_sync.headers_received

    def receive_peer_message(self, peer: Peer) -> Message:
        """Receive and handle one post-handshake message from a ready peer."""
        if not self._is_ready_peer(peer):
            raise ConnectionError(f"Peer {peer.host}:{peer.port} is not ready")
        try:
            message = self.transport.recv_one(peer)
            self.handle_peer_message(peer, message)
        except Exception:
            self.address_book.record_failure(
                peer,
                source=self._source_for_peer(str(peer.host), peer.port),
                failed_at=time.time(),
            )
            self.disconnect_peer(peer)
            raise
        return message

    def handle_peer_message(
            self,
            peer: Peer,
            message: Message,
    ) -> tuple:
        """Apply a received peer message to node networking state."""
        if not self._is_ready_peer(peer):
            raise ConnectionError(f"Peer {peer.host}:{peer.port} is not ready")
        if isinstance(message, Addr):
            merged = self.address_book.merge_net_addresses(message.addr_list)
            self._relay_addr(peer, message)
            return merged
        if isinstance(message, Inv):
            return self._handle_inv(peer, message)
        if isinstance(message, GetData):
            return self._handle_getdata(peer, message)
        if isinstance(message, NotFound):
            for vector in message.items:
                self.inventory_requests.release(vector)
            return ()
        if isinstance(message, Headers):
            return self.header_sync.handle_headers(peer, message)
        if isinstance(message, Txn):
            self.inventory_requests.release_key(("tx", message.tx.txid))
            if self.submit_tx(message.tx, source_peer=peer):
                return (message.tx,)
            logger.warning(
                f"Rejected transaction {message.tx.txid.hex()} "
                f"from {peer.host}:{peer.port}"
            )
            return ()
        if isinstance(message, BlockMessage):
            self.inventory_requests.release_key(("block", message.block.block_id))
            return ()
        return ()

    def _is_ready_peer(self, peer: Peer) -> bool:
        with self._ready_peers_lock:
            return self._ready_peers.get(peer.key) is peer and peer.state is PeerState.READY

    def _relay_addr(self, source_peer: Peer, message: Addr) -> tuple[Peer, ...]:
        candidates = [
            peer for peer in self.ready_peers
            if peer.key != source_peer.key and peer.state is PeerState.READY
        ]
        relay_count = min(self.ADDR_RELAY_PEER_COUNT, len(candidates))
        recipients = tuple(random.sample(candidates, relay_count))
        for peer in recipients:
            self.transport.send(peer, message)
        return recipients

    def _handle_inv(self, peer: Peer, message: Inv) -> tuple[InvVector, ...]:
        requested: list[InvVector] = []
        for vector in message.items:
            if not self._is_requestable_inventory(vector) or self._has_inventory(vector):
                continue
            if self.inventory_requests.claim(vector, peer.key):
                requested.append(vector)
        if requested:
            try:
                self.transport.send(peer, GetData(requested))
            except Exception:
                for vector in requested:
                    self.inventory_requests.release(vector)
                raise
        return tuple(requested)

    def _handle_getdata(self, peer: Peer, message: GetData) -> tuple[InvVector, ...]:
        served: list[InvVector] = []
        missing: list[InvVector] = []
        for vector in message.items:
            if not self._is_requestable_inventory(vector):
                missing.append(vector)
                continue
            key = inventory_key(vector)
            if key is None:
                missing.append(vector)
                continue
            kind, object_hash = key
            if kind == "tx":
                tx = self.mempool.get_tx(object_hash)
                if tx is not None:
                    self.transport.send(peer, Txn(tx))
                    served.append(vector)
                    continue
            elif kind == "block":
                block = self.blockchain.get_block(object_hash)
                if block is not None:
                    self.transport.send(peer, BlockMessage(block))
                    served.append(vector)
                    continue
            missing.append(vector)
        if missing:
            self.transport.send(peer, NotFound(missing))
        return tuple(served)

    def _has_inventory(self, vector: InvVector) -> bool:
        key = inventory_key(vector)
        if key is None:
            return True
        kind, object_hash = key
        if kind == "tx":
            return object_hash in self.mempool
        return self.blockchain.get_block(object_hash) is not None

    @staticmethod
    def _is_requestable_inventory(vector: InvVector) -> bool:
        return vector.inv_type in {
            InvType.MSG_TX,
            InvType.MSG_WITNESS_TX,
            InvType.MSG_BLOCK,
            InvType.MSG_WITNESS_BLOCK,
        }

    def _announce_inventory(
            self,
            vector: InvVector,
            source_peer: Peer | None = None,
    ) -> tuple[Peer, ...]:
        message = Inv([vector])
        sent: list[Peer] = []
        for peer in self.ready_peers:
            if source_peer is not None and peer.key == source_peer.key:
                continue
            try:
                self.transport.send(peer, message)
            except Exception as error:
                logger.warning(
                    f"Failed to announce inventory to {peer.host}:{peer.port}: {error}"
                )
                self.address_book.record_failure(
                    peer,
                    source=self._source_for_peer(str(peer.host), peer.port),
                    failed_at=time.time(),
                )
                self.disconnect_peer(peer)
                continue
            sent.append(peer)
        return tuple(sent)

    # --- Block construction / mining ---------------------------------- #

    def build_block_template(self) -> Block:
        """
        Build a candidate block from the current chain tip and mempool.
        """
        txs = self._get_mempool_transactions()
        height = self.blockchain.height + 1
        fees = self._calculate_mempool_fees(txs)
        coinbase = self._create_coinbase_tx(height, fees)
        prev_block = self.blockchain.tip.block_id if self.blockchain.tip else b"\x00" * BLOCK.PREV_BLOCK

        return Block(
            version=2,
            prev_block=prev_block,
            timestamp=int(time.time()),
            bits=self.blockchain.bits,
            nonce=0,
            txs=[coinbase] + txs,
        )

    def mine_new_block(self) -> Block:
        """
        Compatibility wrapper for callers that currently expect a block template.
        """
        return self.build_block_template()

    def start_mining(self) -> Block | None:
        """
        Build a template and hand it to the miner.
        """
        block_template = self.build_block_template()
        return self.miner.start_mining(block_template, callback=self.on_block_mined)

    def stop_mining(self) -> None:
        """
        Stop the miner if it is active.
        """
        if self.miner and self.miner.is_mining():
            self.miner.stop_mining()

    def _create_coinbase_tx(self, height: int, fees: int) -> Tx:
        block_reward = self.blockchain.calc_subsidy(height)
        coinbase_input = TxIn(
            txid=b"\x00" * TX.TXID,
            vout=0xffffffff,
            scriptsig=self._create_coinbase_script(height),
            sequence=0xffffffff,
        )
        coinbase_output = TxOut(
            amount=block_reward + fees,
            scriptpubkey=self._get_payout_scriptpubkey(),
        )
        return Tx(inputs=[coinbase_input], outputs=[coinbase_output], version=2, locktime=0)

    @staticmethod
    def _create_coinbase_script(height: int) -> bytes:
        height_bytes = height.to_bytes((height.bit_length() + 7) // 8 or 1, "little")
        if height_bytes[-1] & 0x80:
            height_bytes += b"\x00"
        return bytes([len(height_bytes)]) + height_bytes + b"BitClone"

    def _get_payout_scriptpubkey(self) -> bytes:
        """
        Return the mining payout script.

        Wallet-backed payouts will replace this once wallet/node integration is
        ready. For now this keeps block-template creation deterministic enough
        for local development without requiring a wallet.
        """
        return b"\x51"

    # --- Mempool ------------------------------------------------------- #

    def submit_tx(self, tx: bytes | Tx, source_peer: Peer | None = None) -> bool:
        """
        Validate and add a transaction to the mempool, then announce it.

        When the transaction came from a peer, that source is excluded from
        the inventory announcement to avoid echoing its own transaction back.
        """
        accepted = self.mempool.add_tx(tx)
        if not accepted:
            return False
        accepted_tx = Tx.from_bytes(tx) if isinstance(tx, bytes) else tx
        vector = InvVector(InvType.MSG_TX, accepted_tx.txid)
        self.inventory_requests.release(vector)
        self._announce_inventory(vector, source_peer=source_peer)
        return True

    def add_transaction_to_mempool(self, tx: bytes | Tx) -> bool:
        """
        Compatibility wrapper for older callers.
        """
        return self.submit_tx(tx)

    def _get_mempool_transactions(self) -> list[Tx]:
        return self.mempool.get_block_template()

    def _calculate_mempool_fees(self, transactions: list[Tx]) -> int:
        total_fees = 0
        for tx in transactions:
            if tx.txid in self.mempool:
                total_fees += self.mempool.get_fee(tx.txid)
        return total_fees

    # --- Block handling ------------------------------------------------ #

    def submit_block(self, block: Block) -> bool:
        """
        Validate and connect a block. Confirmed mempool transactions are removed
        after a successful active-chain append.
        """
        accepted = self.blockchain.add_block(block)
        if accepted:
            self.mempool.confirm_block([tx.txid for tx in block.txs])
            vector = InvVector(InvType.MSG_BLOCK, block.block_id)
            self.inventory_requests.release(vector)
            self._announce_inventory(vector)
        return accepted

    def on_block_mined(self, block: Block | None) -> bool:
        """
        Miner callback used when a candidate block is found.
        """
        if block is None:
            return False
        return self.submit_block(block)

    # --- Info ---------------------------------------------------------- #

    def status(self) -> dict[str, Any]:
        """
        Return structured node status for CLI/RPC consumers.
        """
        tip = self.blockchain.tip
        best_header = self.blockchain.get_best_header()
        return {
            "started": self.started,
            "network": self.config.network.value,
            "magic_bytes": self.config.magic_bytes.hex(),
            "data_dir": str(self.config.data_dir),
            "db_path": str(self.db_path),
            "block_storage": self.config.block_storage.value,
            "prune_keep_blocks": self.config.prune_keep_blocks,
            "height": self.blockchain.height,
            "tip": tip.block_id[::-1].hex() if tip else None,
            "best_header_height": best_header.height if best_header is not None else -1,
            "best_header": best_header.block_hash[::-1].hex() if best_header is not None else None,
            "header_sync": self.header_sync.state.value,
            "utxo_count": self.blockchain.utxo_count(),
            "mempool_size": len(self.mempool),
            "outbound_peers": len(self.ready_peers),
            "target_outbound": self.peer_manager.target_outbound,
            "bits": self.blockchain.bits.hex(),
            "target": self.blockchain.target.hex(),
            "mining": self.miner.is_mining() if self.miner else False,
        }

    def remote_blockchain_info(self) -> dict | None:
        """Query the configured Bitcoin Core source without starting IBD."""
        return self.blockchain.get_remote_blockchain_info()

    def print_info(self) -> None:
        """
        Print node information for the current CLI-first development phase.
        """
        info = self.status()
        print("=" * 70)
        print("NODE INFO")
        print("=" * 70)
        print(f"Started:           {info['started']}")
        print(f"Blockchain Height: {info['height']}")
        print(f"Tip:               {info['tip']}")
        print(f"UTXO Count:        {info['utxo_count']:,}")
        print(f"Mempool Size:      {info['mempool_size']}")
        print(f"Bits:              {info['bits']}")
        print(f"Mining:            {info['mining']}")
        print("=" * 70)
