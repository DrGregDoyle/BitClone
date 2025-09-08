"""
Loads a given wordlist
"""
from pathlib import Path

DEFAULT_FILE = Path(__file__).parent / "wordlists" / "english.txt"


def load_wordlist(wordlist_file: Path = DEFAULT_FILE) -> list[str]:
    """Return the BIP39 wordlist as a list of strings."""
    with wordlist_file.open(encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]
