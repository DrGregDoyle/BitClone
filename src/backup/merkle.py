"""
A module for Merkle trees
"""

from src.library.hash_functions import hash256


def create_merkle_tree(tx_list: list) -> dict:
    """
    Given a tx_list, we return a merkle tree in dictionary form. The levels of the tree will be the keys, with root =
    0. The values will be a list of 32-byte hash strings, where the parity of the index corresponds to left (even) or
    right (odd).
    """
    # Get height of tree
    height = 0
    while pow(2, height) < len(tx_list):
        height += 1

    # Create merkle branch for all non-zero heights
    merkle_tree = {}
    leaf_list = tx_list.copy()
    while height > 0:

        # Make sure list has even number of elements
        if len(leaf_list) % 2 == 1:
            leaf_list.append(leaf_list[-1])

        # Create current branch
        merkle_tree.update({height: leaf_list})

        # Update leaf list
        leaves = [leaf_list[2 * x] + leaf_list[2 * x + 1] for x in range(len(leaf_list) // 2)]
        leaf_list = [hash256(leaf) for leaf in leaves]

        # Move up in height
        height -= 1

    # Verify and add merkle root
    if len(leaf_list) != 1:
        raise IndexError("More than one value left for merkle root")
    merkle_tree.update({0: leaf_list[0]})

    return merkle_tree


def get_merkle_proof(tx_id: str, tree: dict):
    """
    Given a tx_id and a merkle tree, we return the merkle proof.
    """
    # Get height of tree
    height = max(tree.keys())

    # Track tx_id
    current_id = tx_id

    # Iterate over the levels of the tree
    proof = {}
    while height > 0:
        # Get leaves at height
        leaves = tree.get(height)

        # Verify current_id is in leaves
        if current_id not in leaves:
            raise ValueError(f"tx_id {tx_id} not found at height {height} in given merkle tree.")

        # Find partner_id
        temp_index = leaves.index(current_id)
        parity = temp_index % 2

        # current_id is left leaf
        if parity == 0:
            partner_id = leaves[temp_index + 1]
            concat = current_id + partner_id
        # current_id is right leaf
        else:
            partner_id = leaves[temp_index - 1]
            concat = partner_id + current_id

        # Update proof with partner info
        proof.update({
            height: {
                "tx_id": partner_id,
                "parity": 1 - parity
            }
        })

        # Get info for next level
        current_id = hash256(concat)
        height -= 1

    # Verify merkle root
    merkle_root = tree.get(0)
    if current_id != merkle_root:
        raise ValueError(
            f"Finished with merkle root {current_id} which doesn't agree with merkle root given in tree {merkle_root}")
    proof.update({0: merkle_root})

    return proof


def verify_element(tx_id: str, proof: dict) -> bool:
    """
    Given a tx_id and a proof dict, we return True if the proof dict arrives at the merkle_root.
    """
    height = max(proof.keys())
    current_id = tx_id

    while height > 0:
        # Get partner_dict at height
        partner_dict = proof.get(height)
        parity = partner_dict.get("parity")
        partner_id = partner_dict.get("tx_id")

        # Update current_id
        if parity == 0:  # Partner is left leaf
            concat = partner_id + current_id
        else:  # Partner is right leaf
            concat = current_id + partner_id
        current_id = hash256(concat)

        # Move up in height
        height -= 1

    # Return True/False
    merkle_root = proof.get(0)
    return current_id == merkle_root


if __name__ == "__main__":
    tx_ids = ["0000000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000"]
    mt = create_merkle_tree(tx_ids)
