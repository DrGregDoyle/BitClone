"""
Wordlist methods
"""
# src/data/wordlist.py
from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Dict, Tuple

__all__ = [
    "get_wordlist", "get_index_map", "get_prefix_map",
    "word_index", "is_valid_word",
]

_WORDLIST_PKG = "src.data.wordlists"  # folder with english.txt, etc.
_EXPECTED_LEN = 2048  # BIP-39 list length


@lru_cache(maxsize=None)
def get_wordlist(lang: str = "english") -> Tuple[str, ...]:
    """Return the BIP-39 word list for the given language as an immutable tuple."""
    path = resources.files(_WORDLIST_PKG).joinpath(f"{lang}.txt")
    text = path.read_text(encoding="utf-8")
    words = tuple(w.strip() for w in text.splitlines() if w.strip())
    if len(words) != _EXPECTED_LEN:
        raise ValueError(f"{lang} wordlist must have {_EXPECTED_LEN} words.")
    if len(set(words)) != _EXPECTED_LEN:
        raise ValueError(f"{lang} wordlist contains duplicates.")
    return words


@lru_cache(maxsize=None)
def get_index_map(lang: str = "english") -> Dict[str, int]:
    """Return a mapping word→index for O(1) lookup."""
    wl = get_wordlist(lang)
    return {w: i for i, w in enumerate(wl)}


@lru_cache(maxsize=None)
def get_prefix_map(lang: str = "english") -> Dict[str, int]:
    """Return a mapping from the first 4 letters→index (BIP-39 English uniqueness)."""
    wl = get_wordlist(lang)
    # English guarantees first 4 letters are unique; if you add other languages remove this assumption.
    return {w[:4]: i for i, w in enumerate(wl)}


def word_index(word: str, lang: str = "english", allow_prefix: bool = True) -> int:
    """Return index of word or -1 if not found; optionally resolve by 4-letter prefix."""
    word = word.strip().lower()
    if allow_prefix and len(word) >= 4:
        pm = get_prefix_map(lang)
        idx = pm.get(word[:4])
        if idx is not None and get_wordlist(lang)[idx].startswith(word):
            return idx
    return get_index_map(lang).get(word, -1)


def is_valid_word(word: str, lang: str = "english") -> bool:
    """Return True if the word is in the list."""
    return word_index(word, lang, allow_prefix=False) >= 0
