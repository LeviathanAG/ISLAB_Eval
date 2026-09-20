"""Playfair cipher - standalone, with explicit digraph rules.

The 5x5 square merges I/J.  Plaintext is split into pairs; X is inserted between
equal letters and at the end of an odd message.  Same-row letters move right,
same-column letters move down, and rectangle letters swap columns.  Decryption
reverses row/column movement but cannot automatically distinguish padding X or
J from I.
"""
ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is represented by I


def build_square(keyword: str) -> str:
    cleaned = "".join(c for c in keyword.upper().replace("J", "I") if c in ALPHABET)
    return "".join(dict.fromkeys(cleaned + ALPHABET))


def make_pairs(text: str) -> list[str]:
    text = "".join(c for c in text.upper().replace("J", "I") if c in ALPHABET)
    pairs, index = [], 0
    while index < len(text):
        first = text[index]
        second = text[index + 1] if index + 1 < len(text) else "X"
        if first == second:
            pairs.append(first + ("Q" if first == "X" else "X"))
            index += 1
        else:
            pairs.append(first + second)
            index += 2
    return pairs


def playfair(text: str, keyword: str, decrypt: bool = False) -> str:
    square = build_square(keyword)
    compact = "".join(c for c in text.upper().replace("J", "I") if c in ALPHABET)
    pairs = [compact[i:i+2] for i in range(0, len(compact), 2)] if decrypt else make_pairs(text)
    if decrypt and any(len(pair) != 2 for pair in pairs):
        raise ValueError("Playfair ciphertext length must be even")
    shift, result = (-1 if decrypt else 1), []
    for first, second in pairs:
        r1, c1 = divmod(square.index(first), 5)
        r2, c2 = divmod(square.index(second), 5)
        if r1 == r2:
            c1, c2 = (c1 + shift) % 5, (c2 + shift) % 5
        elif c1 == c2:
            r1, r2 = (r1 + shift) % 5, (r2 + shift) % 5
        else:
            c1, c2 = c2, c1
        result.extend((square[5*r1+c1], square[5*r2+c2]))
    return "".join(result)


if __name__ == "__main__":
    ciphertext = playfair("The key is hidden under the door pad", "GUIDANCE")
    print("square    :", build_square("GUIDANCE"))
    print("ciphertext:", ciphertext)
    print("decrypted :", playfair(ciphertext, "GUIDANCE", decrypt=True))

