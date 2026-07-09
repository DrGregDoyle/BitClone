"""
The Node class - main runtime coordinator for BitClone.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.config import BitCloneConfig, NetworkName
from src.mempool.mempool import MemPool
from src.mining.miner import Miner
from src.network.transport import Transport
from src.tx.tx import Tx, TxIn, TxOut
from src.wallet.wallet import Wallet


class Node:
    """
    Coordinates blockchain, mempool, mining, wallet, and networking components.

    Consensus and policy rules stay in their component modules. Node owns their
    lifecycle and provides a stable API for the future CLI/RPC layer.
    """

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
    ):
        self.config = config or BitCloneConfig.from_options(data_dir=data_dir, network=network, db_path=db_path)
        self.db_path = self.config.db_path

        self.blockchain = blockchain or Blockchain(db_path=self.db_path, blocks_dir=self.config.blocks_dir)
        chain_db_path = getattr(self.blockchain.db, "db_path", self.db_path)
        self.mempool = mempool or MemPool(db_path=chain_db_path, blocks_dir=self.config.blocks_dir)
        self.wallet = wallet
        self.miner = miner or Miner()
        self.transport = transport or Transport()
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

    # --- Block construction / mining ---------------------------------- #

    def build_block_template(self) -> Block:
        """
        Build a candidate block from the current chain tip and mempool.
        """
        txs = self._get_mempool_transactions()
        height = self.blockchain.height + 1
        fees = self._calculate_mempool_fees(txs)
        coinbase = self._create_coinbase_tx(height, fees)
        prev_block = self.blockchain.tip.block_id if self.blockchain.tip else b"\x00" * 32

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
            txid=b"\x00" * 32,
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
