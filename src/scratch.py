"""
SCRATCH
"""

# --- IMPORTS --- #


if __name__ == "__main__":
    num = 18446744073709
    en = EncodedNum(num, encoding="compact")
    print(en.value)
    print(en.display)
