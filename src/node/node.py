"""
The Node class - main runtime coordinator for BitClone.
"""
from __future__ import annotations

import random
import secrets
import time
from pathlib import Path
from typing import Any

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.config import BitCloneConfig, NetworkName
from src.core import BLOCK, NETWORK, TX, NetworkError
from src.mempool.mempool import MemPool
from src.mining.miner import Miner
from src.network.datatypes.network_data import NetAddr
from src.network.datatypes.network_types import PeerState, Services
from src.network.dns_seeds import (
    DEFAULT_DNS_SEED_WORKERS,
    DNSResolver,
    DNSSeedBootstrap,
    DNSSeedResult,
)
from src.network.messages.ctrl_msg import Addr, GetAddr, SendAddrV2, VerAck, Version, WtxidRelay
from src.network.messages.message import Message
from src.network.peer import Peer
from src.network.peer_address_book import PeerAddress, PeerAddressBook, PeerKey, PeerSource
from src.network.transport import Transport
from src.tx.tx import Tx, TxIn, TxOut
from src.wallet.wallet import Wallet


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
    ):
        self.config = config or BitCloneConfig.from_options(
            data_dir=data_dir,
            network=network,
            db_path=db_path,
        )
        self.db_path = self.config.db_path

        self.blockchain = blockchain or Blockchain(db_path=self.db_path, blocks_dir=self.config.blocks_dir)
        chain_db_path = getattr(self.blockchain.db, "db_path", self.db_path)
        self.mempool = mempool or MemPool(db_path=chain_db_path, blocks_dir=self.config.blocks_dir)
        self.wallet = wallet
        self.miner = miner or Miner()
        self.transport = transport or Transport(magic_bytes=self.config.magic_bytes)
        self.address_book = address_book if address_book is not None else PeerAddressBook(self.config.p2p_port)
        self._ready_peers: dict[PeerKey, Peer] = {}
        self.started = False

    # --- Lifecycle ----------------------------------------------------- #

    def start(self) -> None:
        """
        Mark the node runtime as started.

        Networking and background sync loops will be attached here once those
        components exist.
        """
        self.started = True

    def stop(self) -> None:
        """
        Stop active background work without closing persistent resources.
        """
        self.stop_mining()
        for peer in tuple(self._ready_peers.values()):
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

    def connect_peer(self, host: str, port: int | None = None) -> Peer:
        """Connect to a fixed peer and initiate the Bitcoin version handshake."""
        peer = Peer(host, self.config.p2p_port if port is None else port)
        self.address_book.add_peer(peer, source=PeerSource.MANUAL)
        try:
            self.transport.connect(peer)
        except Exception:
            self.address_book.record_failure(peer, failed_at=time.time())
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
            self.address_book.record_failure(peer, failed_at=time.time())
            self.transport.disconnect(peer)
            raise

        self.address_book.record_success(peer, succeeded_at=time.time())
        self._ready_peers[peer.key] = peer
        return peer

    @property
    def ready_peers(self) -> tuple[Peer, ...]:
        """Return a stable snapshot of peers ready for application messages."""
        return tuple(self._ready_peers[key] for key in sorted(self._ready_peers))

    def disconnect_peer(self, peer: Peer) -> None:
        """Disconnect a peer and remove it from the ready-peer registry."""
        self._ready_peers.pop(peer.key, None)
        self.transport.disconnect(peer)

    def receive_peer_message(self, peer: Peer) -> Message:
        """Receive and handle one post-handshake message from a ready peer."""
        if self._ready_peers.get(peer.key) is not peer or peer.state is not PeerState.READY:
            raise ConnectionError(f"Peer {peer.host}:{peer.port} is not ready")
        message = self.transport.recv_one(peer)
        self.handle_peer_message(peer, message)
        return message

    def handle_peer_message(
            self,
            peer: Peer,
            message: Message,
    ) -> tuple[PeerAddress, ...]:
        """Apply a received peer message to node networking state."""
        if self._ready_peers.get(peer.key) is not peer or peer.state is not PeerState.READY:
            raise ConnectionError(f"Peer {peer.host}:{peer.port} is not ready")
        if not isinstance(message, Addr):
            return ()
        merged = self.address_book.merge_net_addresses(message.addr_list)
        self._relay_addr(peer, message)
        return merged

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

    def submit_tx(self, tx: bytes | Tx) -> bool:
        """
        Validate and add a transaction to the mempool.
        """
        return self.mempool.add_tx(tx)

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
        return {
            "started": self.started,
            "network": self.config.network.value,
            "magic_bytes": self.config.magic_bytes.hex(),
            "data_dir": str(self.config.data_dir),
            "db_path": str(self.db_path),
            "height": self.blockchain.height,
            "tip": tip.block_id[::-1].hex() if tip else None,
            "utxo_count": self.blockchain.utxo_count(),
            "mempool_size": len(self.mempool),
            "bits": self.blockchain.bits.hex(),
            "target": self.blockchain.target.hex(),
            "mining": self.miner.is_mining() if self.miner else False,
        }

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
