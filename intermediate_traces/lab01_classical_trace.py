"""Lab 1 classical ciphers with every useful intermediate value printed."""
from __future__ import annotations

from math import gcd

from trace_utils import heading, load_module


playfair = load_module("trace_playfair", "plug_and_play/lab01_classical/playfair.py")


def _letters(text: str) -> str:
    return "".join(character for character in text.upper() if character.isalpha())


def additive_trace(text: str, key: int, decrypt: bool = False) -> str:
    """Print `C=(P+k) mod 26` or `P=(C-k) mod 26` for each letter."""
    cleaned = _letters(text)
    signed_key = -key if decrypt else key
    label = "P" if decrypt else "C"
    print(f"clean={cleaned!r}, key={key % 26}, operation={'decrypt' if decrypt else 'encrypt'}")
    output = []
    for index, character in enumerate(cleaned, 1):
        source = ord(character) - 65
        target = (source + signed_key) % 26
        result = chr(target + 65)
        print(f"{index:2}. {character}={source:2}; ({source:2} {'-' if decrypt else '+'} "
              f"{key % 26:2}) mod 26 = {target:2} -> {result}")
        output.append(result)
    answer = "".join(output)
    print(f"{label}={answer}")
    return answer


def multiplicative_trace(text: str, key: int, decrypt: bool = False) -> str:
    """Print multiplication and the modular inverse used for decryption."""
    if gcd(key, 26) != 1:
        raise ValueError("key must be coprime to 26")
    effective = pow(key, -1, 26) if decrypt else key % 26
    if decrypt:
        print(f"inverse: {key}^-1 mod 26 = {effective}; "
              f"because ({key}*{effective}) mod 26 = 1")
    output = []
    for index, character in enumerate(_letters(text), 1):
        source = ord(character) - 65
        target = source * effective % 26
        result = chr(target + 65)
        print(f"{index:2}. {character}={source:2}; ({source:2}*{effective:2}) mod 26 "
              f"= {target:2} -> {result}")
        output.append(result)
    answer = "".join(output)
    print("result=", answer)
    return answer


def affine_trace(text: str, a: int, b: int, decrypt: bool = False) -> str:
    """Print affine substitution, including `a`'s inverse when decrypting."""
    if gcd(a, 26) != 1:
        raise ValueError("a must be coprime to 26")
    inverse = pow(a, -1, 26)
    print(f"a={a}, b={b % 26}, gcd(a,26)=1, a_inverse={inverse}")
    output = []
    for index, character in enumerate(_letters(text), 1):
        source = ord(character) - 65
        target = inverse * (source - b) % 26 if decrypt else (a * source + b) % 26
        equation = (f"{inverse}*({source}-{b})" if decrypt
                    else f"{a}*{source}+{b}")
        result = chr(target + 65)
        print(f"{index:2}. {character}={source:2}; ({equation}) mod 26 = "
              f"{target:2} -> {result}")
        output.append(result)
    answer = "".join(output)
    print("result=", answer)
    return answer


def vigenere_trace(text: str, keyword: str, decrypt: bool = False) -> str:
    cleaned, key = _letters(text), _letters(keyword)
    if not key:
        raise ValueError("keyword must contain letters")
    stream = (key * ((len(cleaned) + len(key) - 1) // len(key)))[:len(cleaned)]
    print("text      :", cleaned)
    print("key stream:", stream)
    output = []
    for index, (character, key_character) in enumerate(zip(cleaned, stream), 1):
        source, shift = ord(character) - 65, ord(key_character) - 65
        target = (source - shift if decrypt else source + shift) % 26
        result = chr(target + 65)
        print(f"{index:2}. {character}({source:2}) {'-' if decrypt else '+'} "
              f"{key_character}({shift:2}) mod 26 = {target:2}({result})")
        output.append(result)
    answer = "".join(output)
    print("result    :", answer)
    return answer


def autokey_trace(text: str, initial_key: int, decrypt: bool = False) -> str:
    """Print the growing key stream. Decryption appends recovered plaintext."""
    cleaned = _letters(text)
    if not 0 <= initial_key < 26:
        raise ValueError("initial key must be 0..25")
    stream = [initial_key]
    output = []
    for index, character in enumerate(cleaned):
        source = ord(character) - 65
        key_value = stream[index]
        target = (source - key_value if decrypt else source + key_value) % 26
        result = chr(target + 65)
        output.append(result)
        # Encryption extends with original plaintext; decryption with recovered plaintext.
        stream.append(target if decrypt else source)
        print(f"{index + 1:2}. input={character}({source:2}) key={key_value:2} "
              f"-> {result}({target:2}); next appended key={stream[-1]:2}")
    print("key stream used:", stream[:len(cleaned)])
    print("result         :", "".join(output))
    return "".join(output)


def playfair_trace(text: str, keyword: str, decrypt: bool = False) -> str:
    square = playfair.build_square(keyword)
    print("5x5 square (I/J combined):")
    for row in range(5):
        print(" ".join(square[5 * row:5 * row + 5]))
    compact = _letters(text).replace("J", "I")
    pairs = ([compact[i:i + 2] for i in range(0, len(compact), 2)]
             if decrypt else playfair.make_pairs(text))
    print("prepared pairs:", " ".join(pairs))
    shift, output = (-1 if decrypt else 1), []
    for pair in pairs:
        first, second = pair
        r1, c1 = divmod(square.index(first), 5)
        r2, c2 = divmod(square.index(second), 5)
        before = (r1, c1, r2, c2)
        if r1 == r2:
            rule = "same row"
            c1, c2 = (c1 + shift) % 5, (c2 + shift) % 5
        elif c1 == c2:
            rule = "same column"
            r1, r2 = (r1 + shift) % 5, (r2 + shift) % 5
        else:
            rule = "rectangle: swap columns"
            c1, c2 = c2, c1
        transformed = square[5 * r1 + c1] + square[5 * r2 + c2]
        print(f"{pair}: positions {before[:2]},{before[2:]} -> {rule} -> "
              f"{(r1,c1)},{(r2,c2)} -> {transformed}")
        output.append(transformed)
    answer = "".join(output)
    print("result:", answer)
    return answer


def hill_trace(text: str, key: list[list[int]], decrypt: bool = False) -> str:
    """Trace a 2x2 Hill cipher as matrix-vector multiplication modulo 26."""
    if len(key) != 2 or any(len(row) != 2 for row in key):
        raise ValueError("this trace expects a 2x2 key")
    determinant = (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % 26
    if gcd(determinant, 26) != 1:
        raise ValueError("key determinant must be invertible modulo 26")
    active = key
    print(f"K={key}; det(K) mod 26={determinant}; det^-1={pow(determinant,-1,26)}")
    if decrypt:
        inv_det = pow(determinant, -1, 26)
        active = [[key[1][1] * inv_det % 26, -key[0][1] * inv_det % 26],
                  [-key[1][0] * inv_det % 26, key[0][0] * inv_det % 26]]
        print("K^-1 mod 26=", active)
    cleaned = _letters(text)
    cleaned += "X" * (len(cleaned) % 2)
    output = []
    for offset in range(0, len(cleaned), 2):
        pair = cleaned[offset:offset + 2]
        vector = [ord(pair[0]) - 65, ord(pair[1]) - 65]
        raw = [active[0][0] * vector[0] + active[0][1] * vector[1],
               active[1][0] * vector[0] + active[1][1] * vector[1]]
        reduced = [value % 26 for value in raw]
        transformed = "".join(chr(value + 65) for value in reduced)
        print(f"{pair} -> vector {vector}; K*vector={raw}; mod 26={reduced} -> {transformed}")
        output.append(transformed)
    print("result:", "".join(output))
    return "".join(output)


def transposition_trace(text: str, key: list[int], decrypt: bool = False) -> str:
    if sorted(key) != list(range(len(key))):
        raise ValueError("key must be a permutation of 0..n-1")
    size = len(key)
    source = text.upper()
    if not decrypt:
        source += "X" * (-len(source) % size)
        effective = key
    else:
        if len(source) % size:
            raise ValueError("ciphertext must contain complete blocks")
        effective = [key.index(index) for index in range(size)]
        print("inverse key:", effective)
    output = []
    for start in range(0, len(source), size):
        block = source[start:start + size]
        transformed = "".join(block[index] for index in effective)
        print(f"block={block}, indices={effective}, selected="
              f"{[block[index] for index in effective]} -> {transformed}")
        output.append(transformed)
    print("result:", "".join(output))
    return "".join(output)


def known_plaintext_shift_trace(plain_character: str, cipher_character: str) -> int:
    """Recover Caesar/additive key from one aligned known character."""
    p = ord(_letters(plain_character)[0]) - 65
    c = ord(_letters(cipher_character)[0]) - 65
    key = (c - p) % 26
    print(f"known P={plain_character.upper()}={p}, C={cipher_character.upper()}={c}")
    print(f"C=(P+k) mod 26 -> k=(C-P) mod 26=({c}-{p}) mod 26={key}")
    return key


def additive_bruteforce_trace(ciphertext: str) -> list[tuple[int, str]]:
    """Print all 26 Caesar candidates; human language recognition selects one."""
    cleaned = _letters(ciphertext)
    candidates = []
    for key in range(26):
        candidate = "".join(chr((ord(character)-65-key) % 26 + 65)
                            for character in cleaned)
        candidates.append((key, candidate))
        print(f"key={key:2}: {candidate}")
    return candidates


def demo() -> None:
    heading("LAB 1: ADDITIVE")
    additive_trace("HELLO", 3)
    heading("LAB 1: MULTIPLICATIVE")
    multiplicative_trace("HELLO", 5)
    heading("LAB 1: AFFINE")
    affine_trace("HELLO", 5, 8)
    heading("LAB 1: VIGENERE")
    vigenere_trace("ATTACKATDAWN", "LEMON")
    heading("LAB 1: AUTOKEY")
    autokey_trace("HELLO", 7)
    heading("LAB 1: PLAYFAIR")
    playfair_trace("BALLOON", "MONARCHY")
    heading("LAB 1: HILL")
    hill_trace("HELP", [[3, 3], [2, 5]])
    heading("LAB 1: TRANSPOSITION")
    transposition_trace("ABCDEFGHI", [2, 0, 1])
    heading("LAB 1: KNOWN-PLAINTEXT KEY RECOVERY")
    known_plaintext_shift_trace("A", "G")
    heading("LAB 1: ADDITIVE BRUTE FORCE")
    additive_bruteforce_trace("KHOOR")


if __name__ == "__main__":
    demo()
