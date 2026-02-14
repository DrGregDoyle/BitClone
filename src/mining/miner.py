"""
===============================================================================
FILE: src/miner/miner.py
===============================================================================
The Miner class - Performs proof-of-work mining in separate thread
"""
import threading
import time

from src.block.block import Block


class Miner:
    """
    Mining worker - performs proof-of-work computation
    Runs in separate thread, can be interrupted
    """

    def __init__(self):
        self.mining = False
        self.current_block = None
        self.stop_event = threading.Event()
        self.callback = None  # Function to call when block is mined

        # Stats
        self.hashes_computed = 0
        self.start_time = None

    def start_mining(self, block_template: Block, callback=None):
        """
        Begin mining a block

        Args:
            block_template: Block to mine (with nonce=0)
            callback: Function to call when mining completes
                      callback(mined_block) or callback(None) if interrupted
        """
        self.mining = True
        self.stop_event.clear()
        self.current_block = block_template
        self.callback = callback
        self.hashes_computed = 0
        self.start_time = time.time()

        # Get header and target
        header = block_template.get_header()
        target_int = int.from_bytes(header.target, 'big')

        print(f"⛏️  Mining started... (target: {header.target.hex()})")

        # Proof-of-work loop
        while self.mining and not self.stop_event.is_set():
            # Check if hash meets target
            hash_int = int.from_bytes(header.block_id, 'big')

            if hash_int < target_int:
                # Found valid block!
                self.current_block.nonce = header.nonce
                elapsed = time.time() - self.start_time
                hashrate = self.hashes_computed / elapsed if elapsed > 0 else 0

                print(f"✅ Block mined! Nonce: {header.nonce}")
                print(f"   Hash: {header.block_id[::-1].hex()}")
                print(f"   Time: {elapsed:.2f}s")
                print(f"   Hashrate: {hashrate:.2f} H/s")

                if self.callback:
                    self.callback(self.current_block)

                self.mining = False
                return self.current_block

            # Increment nonce and try again
            header.increment()
            self.hashes_computed += 1

            # Periodic progress updates (every 100k hashes)
            if self.hashes_computed % 100_000 == 0:
                elapsed = time.time() - self.start_time
                hashrate = self.hashes_computed / elapsed if elapsed > 0 else 0
                print(f"   Mining... {self.hashes_computed:,} hashes ({hashrate:.0f} H/s)")

        # Mining was interrupted
        print("⏸️  Mining stopped")
        self.current_block = None
        self.mining = False

        if self.callback:
            self.callback(None)

        return None

    def stop_mining(self):
        """
        Gracefully stop mining
        Sets stop event and waits for mining loop to exit
        """
        print("🛑 Stop mining requested...")
        self.stop_event.set()
        self.mining = False

    def get_hashrate(self) -> float:
        """
        Get current hashrate in hashes/second

        Returns:
            Hashrate (H/s)
        """
        if not self.mining or not self.start_time:
            return 0.0

        elapsed = time.time() - self.start_time
        return self.hashes_computed / elapsed if elapsed > 0 else 0.0

    def is_mining(self) -> bool:
        """Check if currently mining"""
        return self.mining
