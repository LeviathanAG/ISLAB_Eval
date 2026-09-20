"""Keyed block transposition and chosen-plaintext key recovery.

Transposition preserves the characters and only changes positions.  A key such
as [2,0,1] means output positions 2,0,1 from each three-character block.
Requirement: the key must be a permutation of 0..block_size-1.
"""


def transposition(text: str, key: list[int], decrypt: bool = False) -> str:
    size = len(key)
    if not size or sorted(key) != list(range(size)):
        raise ValueError("key must contain every index 0..n-1 exactly once")
    if not decrypt:
        text += "X" * (-len(text) % size)
        return "".join(text[start + index]
                       for start in range(0, len(text), size) for index in key)
    if len(text) % size:
        raise ValueError("ciphertext must contain complete blocks")
    inverse = [key.index(index) for index in range(size)]
    return "".join(text[start + index]
                   for start in range(0, len(text), size) for index in inverse)


def recover_key(chosen_plaintext: str, ciphertext: str) -> list[int]:
    """Recover one-block key when chosen plaintext characters are unique."""
    if len(chosen_plaintext) != len(ciphertext):
        raise ValueError("samples must have equal length")
    if len(set(chosen_plaintext)) != len(chosen_plaintext):
        raise ValueError("chosen plaintext characters must be unique")
    if sorted(chosen_plaintext) != sorted(ciphertext):
        raise ValueError("not a transposition: character multisets differ")
    return [chosen_plaintext.index(character) for character in ciphertext]


if __name__ == "__main__":
    # The manual prints CABDEHFGL for abcdefghi; final L is almost certainly a
    # typo because transposition cannot change I into L.  Corrected text:
    print("attack: chosen-plaintext")
    print("key   :", recover_key("abcdefghi", "CABDEHFGI"))

