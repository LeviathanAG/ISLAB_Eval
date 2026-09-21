"""Lab 5 hashing traces, including a complete SHA-256 compression trace."""
from __future__ import annotations

import hashlib
import hmac

from trace_utils import heading


SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
SHA256_INITIAL = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MASK = 0xFFFFFFFF


def manual_hash_trace(text: str) -> int:
    """Trace the lab's DJB2-style 32-bit hash after every character."""
    value = 5381
    print(f"initial h={value} (0x{value:08x})")
    for index, character in enumerate(text, 1):
        before = value
        multiplied = (before << 5) + before
        unmasked = multiplied + ord(character)
        value = unmasked & MASK
        print(f"{index:2}. char={character!r}, ASCII={ord(character):3}; "
              f"h*33={multiplied}; +ASCII={unmasked}; &0xffffffff="
              f"{value} (0x{value:08x})")
    print(f"final decimal={value}; hex={value:08x}")
    return value


def hash_padding_trace(message: bytes, block_bytes: int = 64,
                       length_bytes: int = 8, byteorder: str = "big") -> bytes:
    """Print Merkle-Damgard padding used by SHA-1/SHA-256 style hashes."""
    bit_length = len(message) * 8
    zeros = (block_bytes - length_bytes - (len(message) + 1) % block_bytes) % block_bytes
    padded = message + b"\x80" + b"\x00" * zeros + bit_length.to_bytes(length_bytes, byteorder)
    print(f"original={message.hex()} ({len(message)} bytes={bit_length} bits)")
    print("append one-bit as byte 80")
    print(f"append {zeros} zero bytes until length is {block_bytes-length_bytes} mod {block_bytes}")
    print(f"append original bit length as {length_bytes}-byte {byteorder}-endian: "
          f"{bit_length.to_bytes(length_bytes, byteorder).hex()}")
    print(f"padded length={len(padded)} bytes; blocks={len(padded)//block_bytes}")
    for index in range(0, len(padded), block_bytes):
        print(f"block {index//block_bytes}: {padded[index:index+block_bytes].hex()}")
    return padded


def _ror(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & MASK


def sha256_trace(message: bytes, print_rounds: bool = True) -> bytes:
    """Compute SHA-256 and print W[0..63], T1/T2 and a..h per round."""
    padded = hash_padding_trace(message)
    state = list(SHA256_INITIAL)
    print("initial H:", " ".join(f"{word:08x}" for word in state))
    for block_number, offset in enumerate(range(0, len(padded), 64)):
        block = padded[offset:offset + 64]
        schedule = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        print(f"\nmessage schedule for block {block_number}:")
        for index in range(16, 64):
            s0 = _ror(schedule[index - 15], 7) ^ _ror(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3)
            s1 = _ror(schedule[index - 2], 17) ^ _ror(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10)
            schedule.append((schedule[index - 16] + s0 + schedule[index - 7] + s1) & MASK)
        for start in range(0, 64, 8):
            print(" ".join(f"W{i:02}={schedule[i]:08x}" for i in range(start, start + 8)))

        a, b, c, d, e, f, g, h = state
        if print_rounds:
            print("\nround |       T1       T2 |        a        b        c        d        e        f        g        h")
        for index in range(64):
            sigma1 = _ror(e, 6) ^ _ror(e, 11) ^ _ror(e, 25)
            choose = (e & f) ^ ((~e) & g)
            temporary1 = (h + sigma1 + choose + SHA256_K[index] + schedule[index]) & MASK
            sigma0 = _ror(a, 2) ^ _ror(a, 13) ^ _ror(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (sigma0 + majority) & MASK
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temporary1) & MASK, c, b, a,
                (temporary1 + temporary2) & MASK,
            )
            if print_rounds:
                print(f"{index:5} | {temporary1:08x} {temporary2:08x} | "
                      f"{a:08x} {b:08x} {c:08x} {d:08x} {e:08x} {f:08x} {g:08x} {h:08x}")
        working = (a, b, c, d, e, f, g, h)
        old = state[:]
        state = [(left + right) & MASK for left, right in zip(state, working)]
        print("old H    :", " ".join(f"{word:08x}" for word in old))
        print("working  :", " ".join(f"{word:08x}" for word in working))
        print("new H    :", " ".join(f"{word:08x}" for word in state))
    digest = b"".join(word.to_bytes(4, "big") for word in state)
    print("final digest:", digest.hex())
    print("hashlib check:", hashlib.sha256(message).hexdigest())
    return digest


def multi_hash_trace(message: bytes) -> dict[str, str]:
    """Print input/output sizes for common library hashes."""
    answers = {}
    print(f"exact input bytes ({len(message)}): {message.hex()}")
    for algorithm in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "blake2b"):
        digest = hashlib.new(algorithm, message, usedforsecurity=False).digest()
        answers[algorithm] = digest.hex()
        print(f"{algorithm:8}: {len(digest)*8:3} bits / {len(digest):2} bytes / "
              f"{len(digest.hex()):3} hex chars -> {digest.hex()}")
    return answers


def hmac_trace(message: bytes, key: bytes, algorithm: str = "sha256") -> bytes:
    """Print HMAC key normalization, ipad/opad and inner/outer hashes."""
    block_size = hashlib.new(algorithm).block_size
    print(f"algorithm={algorithm}; hash block size B={block_size} bytes")
    print(f"original key ({len(key)} bytes)={key.hex()}")
    normalized = hashlib.new(algorithm, key).digest() if len(key) > block_size else key
    normalized = normalized.ljust(block_size, b"\x00")
    inner_pad = bytes(byte ^ 0x36 for byte in normalized)
    outer_pad = bytes(byte ^ 0x5C for byte in normalized)
    inner_hash = hashlib.new(algorithm, inner_pad + message).digest()
    tag = hashlib.new(algorithm, outer_pad + inner_hash).digest()
    print("K0 (hash if long, zero-pad to B):", normalized.hex())
    print("K0 xor ipad(36):", inner_pad.hex())
    print("inner hash H((K0 xor ipad)||M):", inner_hash.hex())
    print("K0 xor opad(5c):", outer_pad.hex())
    print("final H((K0 xor opad)||inner):", tag.hex())
    print("stdlib check:", hmac.new(key, message, algorithm).hexdigest())
    return tag


def merkle_trace(items: list[bytes], algorithm: str = "sha256") -> bytes:
    """Print leaf and parent hashes until the Merkle root remains."""
    if not items:
        raise ValueError("at least one item required")
    level = []
    for index, item in enumerate(items):
        leaf = hashlib.new(algorithm, b"\x00" + item).digest()
        level.append(leaf)
        print(f"leaf {index}: H(00||{item!r})={leaf.hex()}")
    depth = 0
    while len(level) > 1:
        if len(level) % 2:
            print(f"level {depth}: odd node count; duplicate final node")
            level.append(level[-1])
        parents = []
        for index in range(0, len(level), 2):
            parent = hashlib.new(algorithm, b"\x01" + level[index] + level[index + 1]).digest()
            print(f"level {depth} pair {index//2}: H(01||{level[index].hex()}||"
                  f"{level[index+1].hex()})={parent.hex()}")
            parents.append(parent)
        level = parents
        depth += 1
    print("Merkle root:", level[0].hex())
    return level[0]


def avalanche_trace(message: bytes, algorithm: str = "sha256") -> int:
    """Flip one input bit and print every differing digest byte/bit count."""
    if not message:
        raise ValueError("message must not be empty")
    changed = bytes([message[0] ^ 1]) + message[1:]
    first = hashlib.new(algorithm, message).digest()
    second = hashlib.new(algorithm, changed).digest()
    total = 0
    print(f"original input={message.hex()}; changed input={changed.hex()} (bit 0 flipped)")
    print("byte | digest 1 | digest 2 | xor | changed bits")
    for index, (left, right) in enumerate(zip(first, second)):
        difference = left ^ right
        count = difference.bit_count()
        total += count
        print(f"{index:4} |    {left:02x}    |    {right:02x}    | {difference:02x}  | {count}")
    print(f"changed={total}/{len(first)*8} bits={total*100/(len(first)*8):.2f}%")
    return total


def pbkdf2_trace(password: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """Print PBKDF2 parameters and result (internal repeated HMACs are library-run)."""
    if len(salt) < 16 or iterations <= 0:
        raise ValueError("use a salt of at least 16 bytes and positive iterations")
    result = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, 32)
    print("PRF=HMAC-SHA256")
    print(f"password UTF-8={password.encode().hex()} (do not print in a real login system)")
    print(f"salt={salt.hex()} ({len(salt)} bytes, public and unique)")
    print(f"iterations={iterations}; derived-key length=32 bytes")
    print("concept: each block XORs U1, U2, ... Uc where U1=PRF(P,S||INT(block))")
    print("derived key:", result.hex())
    return result


def socket_framing_trace(message: bytes) -> bytes:
    """Show the length-prefix and digest fields used by the integrity socket lab."""
    length = len(message).to_bytes(4, "big")
    digest = hashlib.sha256(message).digest()
    frame = length + message + digest
    print(f"length integer={len(message)} -> 4-byte big-endian={length.hex()}")
    print(f"payload={message.hex()}")
    print(f"SHA-256 payload={digest.hex()}")
    print(f"wire frame=length||payload||digest={frame.hex()}")
    print("receiver: read 4 bytes -> exact payload length -> 32 digest bytes -> compare")
    return frame


def demo() -> None:
    heading("LAB 5: MANUAL 32-BIT HASH")
    manual_hash_trace("ABC")
    heading("LAB 5: COMMON HASH OUTPUTS")
    multi_hash_trace(b"abc")
    heading("LAB 5: SHA-256 COMPLETE TRACE")
    sha256_trace(b"abc")
    heading("LAB 5: HMAC")
    hmac_trace(b"message", b"secret-key")
    heading("LAB 5: MERKLE TREE")
    merkle_trace([b"A", b"B", b"C"])
    heading("LAB 5: AVALANCHE EFFECT")
    avalanche_trace(b"ABC")
    heading("LAB 5: PBKDF2")
    pbkdf2_trace("exam-password", bytes.fromhex("00112233445566778899aabbccddeeff"))
    heading("LAB 5: SOCKET FRAME")
    socket_framing_trace(b"multipart data")


if __name__ == "__main__":
    demo()
