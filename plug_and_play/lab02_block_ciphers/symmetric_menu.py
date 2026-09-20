"""Complete menu-driven AES/DES/3DES program.

Install PyCryptodome first: ``pip install pycryptodome``.

The encrypted result is printed as one JSON packet containing every public
value required for decryption: algorithm, mode, IV/nonce, authentication tag,
and ciphertext.  The secret key is deliberately not included.  Copy the JSON
packet into the Decrypt option and enter the same key.

INPUT SUMMARY
-------------
* Plaintext: normal text, converted with UTF-8 ``encode()``.
* Key: hexadecimal.  Two hex characters represent one byte.
  AES: 32/48/64 hex chars. DES: 16. 3DES: 32 or 48.
* Ciphertext: hexadecimal because encrypted bytes may not be printable.
* CBC IV: one full block (AES 16 bytes, DES/3DES 8 bytes), random and public.
* CTR nonce: unique per key; this program uses 8 bytes for AES and 4 for DES.
* GCM nonce: normally 12 bytes; tag is required for authenticated decryption.
* ECB/CBC use PKCS#7 padding. CTR/GCM do not use padding.
"""
from __future__ import annotations

import json


KEY_LENGTHS = {"AES": (16, 24, 32), "DES": (8,), "3DES": (16, 24)}
BLOCK_SIZE = {"AES": 16, "DES": 8, "3DES": 8}


def parse_hex(value: str, label: str) -> bytes:
    """Convert printable hexadecimal into raw bytes with a useful error."""
    value = value.strip().replace(" ", "")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} must contain an even number of hex digits") from error


def validate_key(algorithm: str, key: bytes) -> bytes:
    """Check byte length and normalize DES parity where the library requires it."""
    allowed = KEY_LENGTHS[algorithm]
    if len(key) not in allowed:
        sizes = "/".join(str(size * 2) for size in allowed)
        raise ValueError(f"{algorithm} key must contain {sizes} hexadecimal characters")
    if algorithm == "3DES":
        from Crypto.Cipher import DES3
        try:
            key = DES3.adjust_key_parity(key)
        except ValueError as error:
            raise ValueError("3DES key degenerates to single DES; use distinct subkeys") from error
    return key


def generate_key(algorithm: str) -> bytes:
    """Generate a sensible default key: AES-128, DES-64, or three-key 3DES."""
    from Crypto.Random import get_random_bytes
    size = {"AES": 16, "DES": 8, "3DES": 24}[algorithm]
    while True:
        try:
            return validate_key(algorithm, get_random_bytes(size))
        except ValueError:  # Extremely unlikely degenerate 3DES key; retry.
            pass


def read_key(algorithm: str, allow_generate: bool) -> bytes:
    print("1. Enter key as hexadecimal")
    print("2. Enter key as literal text")
    if allow_generate:
        print("3. Generate a random key")
    option = input("Key option: ").strip()
    if option == "3" and allow_generate:
        key = generate_key(algorithm)
        print("SAVE THIS KEY HEX:", key.hex())
        return key
    if option == "2":
        key = input("Enter literal key text: ").encode("utf-8")
    else:
        key = parse_hex(input("Enter key hex: "), "key")
    return validate_key(algorithm, key)


def cipher_module(algorithm: str):
    """Return the PyCryptodome module selected by the menu."""
    from Crypto.Cipher import AES, DES, DES3
    return {"AES": AES, "DES": DES, "3DES": DES3}[algorithm]


def encrypt_message(plaintext: bytes, key: bytes, algorithm: str,
                    mode: str, initial_value: bytes | None = None) -> dict[str, str]:
    """Encrypt bytes and return a JSON-serializable packet.

    IVs/nonces are generated here, transmitted with ciphertext, and never
    treated as passwords.  GCM is restricted to AES in this exam program.
    """
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad

    algorithm, mode = algorithm.upper(), mode.upper()
    key = validate_key(algorithm, key)
    module = cipher_module(algorithm)
    packet = {"algorithm": algorithm, "mode": mode}

    if mode == "ECB":
        cipher = module.new(key, module.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE[algorithm]))

    elif mode == "CBC":
        iv = initial_value or get_random_bytes(BLOCK_SIZE[algorithm])
        if len(iv) != BLOCK_SIZE[algorithm]:
            raise ValueError(f"{algorithm} CBC IV must be {BLOCK_SIZE[algorithm]} bytes")
        cipher = module.new(key, module.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext, BLOCK_SIZE[algorithm]))
        packet["iv"] = iv.hex()

    elif mode == "CTR":
        nonce_size = 8 if algorithm == "AES" else 4
        nonce = initial_value or get_random_bytes(nonce_size)
        if not 1 <= len(nonce) < BLOCK_SIZE[algorithm]:
            raise ValueError(f"CTR nonce must be shorter than the {BLOCK_SIZE[algorithm]}-byte block")
        cipher = module.new(key, module.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        packet["nonce"] = nonce.hex()

    elif mode == "GCM":
        if algorithm != "AES":
            raise ValueError("Use GCM with AES in this menu")
        nonce = initial_value or get_random_bytes(12)
        if len(nonce) != 12:
            raise ValueError("This menu uses the recommended 12-byte GCM nonce")
        cipher = module.new(key, module.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        packet.update(nonce=nonce.hex(), tag=tag.hex())

    else:
        raise ValueError("mode must be ECB, CBC, CTR, or GCM")

    packet["ciphertext"] = ciphertext.hex()
    return packet


def decrypt_message(packet: dict[str, str], key: bytes) -> bytes:
    """Reverse :func:`encrypt_message`; GCM raises if data/tag was modified."""
    from Crypto.Util.Padding import unpad

    algorithm, mode = packet["algorithm"].upper(), packet["mode"].upper()
    key = validate_key(algorithm, key)
    module = cipher_module(algorithm)
    ciphertext = parse_hex(packet["ciphertext"], "ciphertext")

    if mode == "ECB":
        padded = module.new(key, module.MODE_ECB).decrypt(ciphertext)
        return unpad(padded, BLOCK_SIZE[algorithm])

    if mode == "CBC":
        iv = parse_hex(packet["iv"], "IV")
        if len(iv) != BLOCK_SIZE[algorithm]:
            raise ValueError(f"{algorithm} CBC IV must be {BLOCK_SIZE[algorithm]} bytes")
        padded = module.new(key, module.MODE_CBC, iv=iv).decrypt(ciphertext)
        return unpad(padded, BLOCK_SIZE[algorithm])

    if mode == "CTR":
        nonce = parse_hex(packet["nonce"], "nonce")
        return module.new(key, module.MODE_CTR, nonce=nonce).decrypt(ciphertext)

    if mode == "GCM":
        nonce = parse_hex(packet["nonce"], "nonce")
        tag = parse_hex(packet["tag"], "tag")
        return module.new(key, module.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)

    raise ValueError("unknown mode in packet")


def choose(prompt: str, options: tuple[str, ...]) -> str:
    """Numbered validated menu input."""
    for number, option in enumerate(options, 1):
        print(f"{number}. {option}")
    value = input(prompt).strip()
    if not value.isdigit() or not 1 <= int(value) <= len(options):
        raise ValueError("invalid menu choice")
    return options[int(value) - 1]


def main():
    while True:
        print("\n=== SYMMETRIC CIPHER MENU ===")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        action = input("Enter choice: ").strip()
        try:
            if action == "1":
                algorithm = choose("Algorithm: ", ("AES", "DES", "3DES"))
                modes = ("ECB", "CBC", "CTR", "GCM") if algorithm == "AES" else ("ECB", "CBC", "CTR")
                mode = choose("Mode: ", modes)
                key = read_key(algorithm, allow_generate=True)
                plaintext = input("Enter plaintext: ").encode("utf-8")
                initial_value = None
                if mode != "ECB":
                    label = "IV" if mode == "CBC" else "nonce"
                    supplied = input(f"Enter {label} hex, or press Enter to generate: ").strip()
                    initial_value = parse_hex(supplied, label) if supplied else None
                packet = encrypt_message(plaintext, key, algorithm, mode, initial_value)
                print("COPY THIS ENCRYPTED PACKET:")
                print(json.dumps(packet))

            elif action == "2":
                packet = json.loads(input("Paste encrypted JSON packet: "))
                algorithm = packet["algorithm"].upper()
                key = read_key(algorithm, allow_generate=False)
                plaintext = decrypt_message(packet, key)
                print("Plaintext:", plaintext.decode("utf-8"))

            elif action == "3":
                break

            else:
                print("Invalid choice")
        except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
            print("Error:", error)


if __name__ == "__main__":
    main()
