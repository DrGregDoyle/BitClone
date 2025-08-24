"""
These are tests for /data/merkle.py written entirely by ChatGPT-5
"""
import hashlib

import pytest

from src.backup.data.merkle import MerkleTree


def ds(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def make_leaves(n: int) -> list[bytes]:
    # 32-byte “txids” (not reversed): sha256("T{i}")
    return [hashlib.sha256(f"T{i}".encode()).digest() for i in range(n)]


def manual_merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        raise ValueError("empty")
    cur = list(leaves)
    if len(cur) == 1:
        return cur[0]
    while len(cur) > 1:
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        nxt = [ds(cur[i] + cur[i + 1]) for i in range(0, len(cur), 2)]
        cur = nxt
    return cur[0]


def verify_proof(leaf: bytes, proof: list[tuple[bytes, str]]) -> bytes:
    h = leaf
    for sib, pos in proof:
        h = ds(sib + h) if pos == "left" else ds(h + sib)
    return h


def test_single_leaf_root_is_leaf():
    leaves = make_leaves(1)
    t = MerkleTree(leaves)
    assert t.merkle_root == leaves[0]
    assert t.mutated is False


@pytest.mark.parametrize("n", [2, 3, 4, 7, 8])
def test_root_matches_manual(n):
    leaves = make_leaves(n)
    t = MerkleTree(leaves)
    assert t.merkle_root == manual_merkle_root(leaves)


def test_odd_duplication_does_not_set_mutated():
    leaves = make_leaves(3)  # last duplicated internally
    t = MerkleTree(leaves)
    assert t.mutated is False


def test_mutated_true_when_distinct_siblings_equal():
    # Two distinct leaves with identical bytes => mutated must be True
    a = make_leaves(1)[0]
    leaves = [a, a]  # siblings are equal but not the odd-dup case
    t = MerkleTree(leaves)
    assert t.mutated is True
    # Sanity root
    assert t.merkle_root == ds(a + a)


@pytest.mark.parametrize("n", [3, 4, 7])
def test_proofs_verify_for_all_leaves(n):
    leaves = make_leaves(n)
    t = MerkleTree(leaves)
    for i, leaf in enumerate(leaves):
        proof = t.get_merkle_proof(leaf)
        computed_root = verify_proof(leaf, proof)
        assert computed_root == t.merkle_root


def test_get_merkle_proof_raises_if_not_found():
    leaves = make_leaves(4)
    t = MerkleTree(leaves)
    rogue = hashlib.sha256(b"rogue").digest()
    with pytest.raises(ValueError):
        t.get_merkle_proof(rogue)
