"""
The Node class - Main coordinator for the blockchain node
"""
import time

from src.block.block import Block
from src.blockchain.blockchain import Blockchain
from src.mempool.mempool import MemPool
from src.tx.tx import Transaction, TxIn, TxOut


# from src.wallet.wallet import Wallet  # Future import
# from src.miner.miner import Miner     # Future import


class Node:
    """
    Bitcoin node - coordinates blockchain, wallet, mempool, and mining
    """

    def __init__(self, blockchain: Blockchain = None, wallet=None):
        # -- TODO: Update inputs to take db_path and wallet_obj
        # -- TODO: Make blockchain and mempool use the same db
        self.blockchain = blockchain or Blockchain()
        self.wallet = wallet  # Will hold wallet instance
        self.mempool = MemPool()  # List of unconfirmed transactions
        self.current_difficulty = b'\x1d\x00\xff\xff'  # Default difficulty

        # Mining thread (to be implemented)
        self.miner = None  # Will be Miner instance
        self.miner_thread = None

    # --- BLOCK CONSTRUCTION --- #

    def mine_new_block(self):
        """
        Build block template and start mining
        Main entry point for mining a new block
        """
        # 1. Get transactions from mempool
        txs = self._get_mempool_transactions()

        # 2. Create coinbase transaction
        height = self.blockchain.height + 1
        fees = self._calculate_fees(txs)
        coinbase = self._create_coinbase_tx(height, fees)

        # 3. Get previous block hash
        prev_block = self.blockchain.tip.get_header().block_id if self.blockchain.tip else b'\x00' * 32

        # 4. Build block template
        block_template = Block(
            version=2,
            prev_block=prev_block,
            timestamp=int(time.time()),
            bits=self.current_difficulty,
            nonce=0,
            txs=[coinbase] + txs
        )

        # 5. Pass to miner thread (future implementation)
        # self.miner_thread = threading.Thread(target=self.miner.start_mining, args=(block_template,))
        # self.miner_thread.start()

        return block_template

    def _create_coinbase_tx(self, height: int, fees: int) -> Transaction:
        """
        Create coinbase transaction for new block

        Args:
            height: Block height being mined
            fees: Total fees from mempool transactions

        Returns:
            Coinbase Transaction
        """
        # Calculate block reward with halving
        block_reward = self._calculate_block_reward(height)

        # Coinbase input (special format)
        coinbase_input = TxIn(
            txid=b'\x00' * 32,
            vout=0xffffffff,
            scriptsig=self._create_coinbase_script(height),
            sequence=0xffffffff
        )

        # Coinbase output (reward + fees to wallet address)
        payout_scriptpubkey = self._get_payout_address()
        coinbase_output = TxOut(
            amount=block_reward + fees,
            scriptpubkey=payout_scriptpubkey
        )

        return Transaction(
            inputs=[coinbase_input],
            outputs=[coinbase_output],
            version=2,
            locktime=0
        )

    def _create_coinbase_script(self, height: int) -> bytes:
        """
        Create coinbase scriptsig (includes block height per BIP34)

        Args:
            height: Block height

        Returns:
            Coinbase scriptsig bytes
        """
        # Encode height as compact size
        height_bytes = height.to_bytes((height.bit_length() + 7) // 8, 'little')
        return bytes([len(height_bytes)]) + height_bytes + b'BitClone'

    def _calculate_block_reward(self, height: int) -> int:
        """
        Calculate block subsidy with halving every 210,000 blocks

        Args:
            height: Block height

        Returns:
            Block reward in satoshis
        """
        halvings = height // 210_000
        if halvings >= 64:
            return 0
        return 5_000_000_000 >> halvings  # 50 BTC (5 billion sats) >> halvings

    def _get_payout_address(self) -> bytes:
        """
        Get scriptpubkey for coinbase payout

        Returns:
            Scriptpubkey bytes (from wallet when implemented)
        """
        # TODO: Get from wallet
        # return self.wallet.get_scriptpubkey()

        # Temporary: return dummy P2PKH scriptpubkey
        from secrets import token_bytes
        pubkey_hash = token_bytes(20)
        return b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'

    # --- MEMPOOL MANAGEMENT --- #

    def _get_mempool_transactions(self) -> list[Transaction]:
        """
        Get transactions from mempool to include in block

        Returns:
            List of transactions (ordered by fee priority)
        """
        # TODO: Implement fee-based prioritization
        return self.mempool.copy()

    def add_transaction_to_mempool(self, tx: Transaction):
        """Add a transaction to the mempool"""
        # TODO: Validate transaction before adding
        self.mempool.append(tx)

    def _calculate_fees(self, transactions: list[Transaction]) -> int:
        """
        Calculate total fees from transactions

        Args:
            transactions: List of transactions

        Returns:
            Total fees in satoshis
        """
        total_fees = 0
        for tx in transactions:
            # Sum inputs
            input_sum = 0
            for inp in tx.inputs:
                utxo = self.blockchain.get_utxo(inp.outpoint)
                if utxo:
                    input_sum += utxo.amount

            # Sum outputs
            output_sum = sum(out.amount for out in tx.outputs)

            # Fee is difference
            total_fees += (input_sum - output_sum)

        return total_fees

    # --- BLOCK HANDLING --- #

    def on_block_mined(self, block: Block):
        """
        Called when miner completes a block

        Args:
            block: Mined block
        """
        # Add to blockchain
        success = self.blockchain.add_block(block)

        if success:
            # Remove mined transactions from mempool
            mined_txids = {tx.txid for tx in block.txs}
            self.mempool = [tx for tx in self.mempool if tx.txid not in mined_txids]

            print(f"✅ Block mined at height {self.blockchain.height}")

        return success

    def stop_mining(self):
        """Stop the current mining operation"""
        # TODO: Signal miner thread to stop
        # if self.miner:
        #     self.miner.stop_mining()
        pass

    # --- INFO --- #

    def print_info(self):
        """Print node information"""
        print("=" * 70)
        print("NODE INFO")
        print("=" * 70)
        print(f"Blockchain Height: {self.blockchain.height}")
        print(f"UTXO Count:        {self.blockchain.utxo_count():,}")
        print(f"Mempool Size:      {len(self.mempool)}")
        print(f"Difficulty:        {self.current_difficulty.hex()}")
        print("=" * 70)
