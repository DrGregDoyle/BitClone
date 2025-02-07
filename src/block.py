"""
Block and MerkleTree classes
"""
import math

from src.library.hash_functions import hash256


class MerkleTree:

    def __init__(self, id_list: list):
        self.tree = self._create_tree(id_list)
        self.merkle_root = self.tree.get(0)[0][::-1]  # Root is displayed in little-endian

    def _create_tree(self, id_list):
        """
        Create merkle tree dictionary, where the keys of the dict are integer values corresponding to the level of
        the tree.
        """
        # Clean list
        clean_list = self._clean_list(id_list)

        # Deduce height
        height = math.ceil(math.log2(len(clean_list)))
        print(f"HEIGHT: {height}")

        tree_dict = {}
        # Create tree
        while height > 0:
            # Check parity of list
            if len(clean_list) % 2 != 0:
                clean_list.append(clean_list[-1])

            # Add clean_list to dict at current height
            tree_dict[height] = [clean_list]

            # Hash clean_list pairs and create new clean_list
            clean_list = [hash256(clean_list[x] + clean_list[x + 1]) for x in range(0, len(clean_list), 2)]

            # Subtract height
            height -= 1

        # Check height outside of loop
        if height != 0:
            raise ValueError("Height incorrect after creating tree")

        # Add merkle root and return
        tree_dict[height] = clean_list
        return tree_dict

    def _clean_list(self, id_list) -> list:
        """
        Takes every id from the id list, verifies its bytes and reverses the order.
        If an id is neither a bytes object nor a valid hexadecimal string, raises a ValueError.
        """
        clean_list = []
        for _id in id_list:
            if isinstance(_id, str):
                try:
                    _bytesid = bytes.fromhex(_id)
                except ValueError:
                    raise ValueError(f"Invalid hexadecimal string: {_id}")
            elif isinstance(_id, bytes):
                _bytesid = _id
            else:
                raise ValueError(f"Invalid ID type: {_id} (Expected bytes or hex string)")

            clean_list.append(_bytesid[::-1])  # Reverse byte order

        return clean_list


# -- TESTING
if __name__ == "__main__":
    id_list = [
        "dbb3501e1515fd274f343a87df1382c62879b6a28de99b5713a98993ce02d38b",
        "dbb3501e1515fd274f343a87df1382c62879b6a28de99b5713a98993ce02d38b",
        "dbb3501e1515fd274f343a87df1382c62879b6a28de99b5713a98993ce02d38b"
    ]
    t = MerkleTree(id_list)
    print(f"MERKLE ROOT: {t.merkle_root.hex()}")
