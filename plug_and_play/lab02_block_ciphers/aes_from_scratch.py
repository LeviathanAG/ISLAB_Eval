"""Readable AES-128/192/256 implementation from scratch.

INPUT RULES
-----------
* AES always encrypts one 16-byte (128-bit) block at a time.
* Keys are exactly 16, 24, or 32 bytes for AES-128, AES-192, AES-256.
* A message of arbitrary length needs a mode and usually padding.  The helpers
  at the bottom demonstrate ECB only because it exposes the core algorithm;
  use AES-GCM from ``library_ciphers.py`` for real applications.

ROUND STRUCTURE
---------------
State is 16 bytes arranged column-first as a 4x4 matrix.  Encryption performs:
  1. AddRoundKey before the loop.
  2. SubBytes -> ShiftRows -> MixColumns -> AddRoundKey for main rounds.
  3. SubBytes -> ShiftRows -> AddRoundKey in the last round.
AES-128/192/256 use 10/12/14 rounds.  Decryption applies inverse operations in
reverse order.  Arithmetic inside MixColumns is in GF(2^8) modulo x^8+x^4+x^3+x+1
(binary 0x11B), not ordinary integer multiplication.
"""


def gf_multiply(a: int, b: int) -> int:
    """Multiply two bytes in AES's finite field GF(2^8)."""
    answer = 0
    while b:
        if b & 1:
            answer ^= a
        a = (a << 1) ^ (0x11B if a & 0x80 else 0)
        b >>= 1
    return answer & 0xFF


def gf_power(value: int, exponent: int) -> int:
    answer = 1
    while exponent:
        if exponent & 1:
            answer = gf_multiply(answer, value)
        value = gf_multiply(value, value)
        exponent >>= 1
    return answer


def build_sbox() -> list[int]:
    """Generate the AES S-box: multiplicative inverse then affine transform."""
    box = []
    for byte in range(256):
        inverse = gf_power(byte, 254) if byte else 0
        transformed = inverse ^ 0x63
        for shift in range(1, 5):
            rotated = ((inverse << shift) | (inverse >> (8-shift))) & 0xFF
            transformed ^= rotated
        box.append(transformed)
    return box


SBOX = build_sbox()
INVERSE_SBOX = [SBOX.index(value) for value in range(256)]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def rotate_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def substitute_word(word: list[int]) -> list[int]:
    return [SBOX[byte] for byte in word]


def expand_key(key: bytes) -> tuple[list[bytes], int]:
    """Expand the original key into one 16-byte key for every AES round.

    Nk is original key words: 4/6/8.  Nr=Nk+6 gives 10/12/14 rounds.
    Every Nk-th word uses RotWord, SubWord, and Rcon.  AES-256 also applies
    SubWord halfway through each eight-word group.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be exactly 16, 24, or 32 bytes")
    key_words = len(key) // 4
    rounds = key_words + 6
    words = [list(key[index:index+4]) for index in range(0, len(key), 4)]
    round_constant = 1
    required_words = 4 * (rounds + 1)
    while len(words) < required_words:
        temporary = words[-1].copy()
        index = len(words)
        if index % key_words == 0:
            temporary = substitute_word(rotate_word(temporary))
            temporary[0] ^= round_constant
            round_constant = gf_multiply(round_constant, 2)
        elif key_words == 8 and index % key_words == 4:
            temporary = substitute_word(temporary)
        previous = words[index - key_words]
        words.append([a ^ b for a, b in zip(previous, temporary)])
    round_keys = [bytes(sum(words[index:index+4], []))
                  for index in range(0, required_words, 4)]
    return round_keys, rounds


def sub_bytes(state: bytes, inverse: bool = False) -> bytes:
    box = INVERSE_SBOX if inverse else SBOX
    return bytes(box[byte] for byte in state)


def shift_rows(state: bytes, inverse: bool = False) -> bytes:
    """Row r rotates left by r; inverse rotates right by r.

    Index 4*column+row is used because AES stores state column-first.
    """
    direction = -1 if inverse else 1
    return bytes(state[4*((column + direction*row) % 4) + row]
                 for column in range(4) for row in range(4))


def mix_columns(state: bytes, inverse: bool = False) -> bytes:
    """Multiply each state column by the fixed AES matrix in GF(2^8)."""
    first_row = [14, 11, 13, 9] if inverse else [2, 3, 1, 1]
    output = []
    for column_number in range(4):
        column = state[4*column_number:4*column_number+4]
        for row in range(4):
            value = 0
            for item in range(4):
                value ^= gf_multiply(column[item], first_row[(item-row) % 4])
            output.append(value)
    return bytes(output)


def add_round_key(state: bytes, round_key: bytes) -> bytes:
    """XOR is its own inverse, so encryption and decryption use the same step."""
    return xor_bytes(state, round_key)


def aes_encrypt_block(block: bytes, key: bytes, trace: bool = False):
    """Encrypt exactly one 16-byte block; optionally return intermediate states."""
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    round_keys, rounds = expand_key(key)
    states = []
    state = add_round_key(block, round_keys[0])
    states.append(("round 0 add_round_key", state.hex()))
    for number in range(1, rounds + 1):
        state = sub_bytes(state)
        states.append((f"round {number} sub_bytes", state.hex()))
        state = shift_rows(state)
        states.append((f"round {number} shift_rows", state.hex()))
        if number != rounds:
            state = mix_columns(state)
            states.append((f"round {number} mix_columns", state.hex()))
        state = add_round_key(state, round_keys[number])
        states.append((f"round {number} add_round_key", state.hex()))
    return (state, states) if trace else state


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    round_keys, rounds = expand_key(key)
    state = add_round_key(block, round_keys[rounds])
    for number in range(rounds - 1, -1, -1):
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)
        state = add_round_key(state, round_keys[number])
        if number != 0:
            state = mix_columns(state, inverse=True)
    return state


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Always append 1..block_size bytes; every added byte equals the count."""
    count = block_size - len(data) % block_size
    return data + bytes([count]) * count


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    count = data[-1] if data else 0
    if not 1 <= count <= block_size or data[-count:] != bytes([count]) * count:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-count]


def aes_ecb_encrypt(message: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(message)
    return b"".join(aes_encrypt_block(padded[i:i+16], key)
                    for i in range(0, len(padded), 16))


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16:
        raise ValueError("AES ciphertext must contain complete 16-byte blocks")
    padded = b"".join(aes_decrypt_block(ciphertext[i:i+16], key)
                      for i in range(0, len(ciphertext), 16))
    return pkcs7_unpad(padded)


if __name__ == "__main__":
    # NIST AES-128 known-answer test.  Matching this value validates core rounds.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
    ciphertext, steps = aes_encrypt_block(plaintext, key, trace=True)
    print("ciphertext:", ciphertext.hex())
    print("expected  :", expected)
    print("decrypted :", aes_decrypt_block(ciphertext, key).hex())
    print("first four intermediate states:")
    for label, value in steps[:4]:
        print(label, value)

