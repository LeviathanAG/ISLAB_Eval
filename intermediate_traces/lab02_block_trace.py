"""Lab 2 AES, DES, 3DES and CBC traces with complete intermediate output."""
from __future__ import annotations

from trace_utils import aes_matrix, heading, load_module


aes = load_module("trace_aes", "plug_and_play/lab02_block_ciphers/aes_from_scratch.py")
des = load_module("trace_des", "plug_and_play/lab02_block_ciphers/des_from_scratch.py")


def aes_trace(block: bytes, key: bytes) -> bytes:
    """Print key expansion and every AES encryption transformation."""
    round_keys, rounds = aes.expand_key(key)
    print(f"AES-{len(key) * 8}; rounds={rounds}")
    print("input block:", block.hex())
    print(aes_matrix(block))
    print("\nexpanded round keys:")
    for number, round_key in enumerate(round_keys):
        print(f"K{number:02}={round_key.hex()}")

    state = block
    print("\nround 0 input:", state.hex())
    state = aes.add_round_key(state, round_keys[0])
    print("round 0 AddRoundKey:", state.hex())
    for number in range(1, rounds + 1):
        print(f"\n-- AES round {number} --")
        print("input       :", state.hex())
        state = aes.sub_bytes(state)
        print("SubBytes    :", state.hex())
        state = aes.shift_rows(state)
        print("ShiftRows   :", state.hex())
        if number != rounds:
            state = aes.mix_columns(state)
            print("MixColumns  :", state.hex())
        else:
            print("MixColumns  : skipped in final round")
        print("round key   :", round_keys[number].hex())
        state = aes.add_round_key(state, round_keys[number])
        print("AddRoundKey :", state.hex())
        print("state matrix:\n" + aes_matrix(state))
    print("ciphertext:", state.hex())
    print("decrypted :", aes.aes_decrypt_block(state, key).hex())
    return state


def des_key_schedule_trace(key: bytes) -> list[int]:
    """Print PC-1, C/D rotations and PC-2 for all 16 keys."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes")
    key64 = int.from_bytes(key, "big")
    reduced = des.permute(key64, des.PC1, 64)
    left, right = reduced >> 28, reduced & ((1 << 28) - 1)
    print(f"key64={key64:016X}")
    print(f"PC-1 (parity removed)={reduced:014X}")
    print(f"C0={left:07X}, D0={right:07X}")
    keys = []
    for number, rotation in enumerate(des.ROTATIONS, 1):
        left = des.rotate_left_28(left, rotation)
        right = des.rotate_left_28(right, rotation)
        round_key = des.permute((left << 28) | right, des.PC2, 56)
        keys.append(round_key)
        print(f"round {number:2}: shift={rotation}, C={left:07X}, D={right:07X}, "
              f"K={round_key:012X}")
    return keys


def _des_f_trace(right: int, round_key: int) -> int:
    expanded = des.permute(right, des.E, 32)
    mixed = expanded ^ round_key
    print(f"  E(R)       ={expanded:012X}")
    print(f"  K          ={round_key:012X}")
    print(f"  E(R) xor K ={mixed:012X}")
    combined = 0
    pieces = []
    for box_number in range(8):
        chunk = (mixed >> (42 - 6 * box_number)) & 0x3F
        row = ((chunk >> 5) << 1) | (chunk & 1)
        column = (chunk >> 1) & 0xF
        value = des.DES_S[box_number][row * 16 + column]
        combined = (combined << 4) | value
        pieces.append(f"S{box_number + 1}({chunk:06b}:r{row},c{column})={value:X}")
    print("  " + ", ".join(pieces))
    print(f"  S-box out  ={combined:08X}")
    result = des.permute(combined, des.P, 32)
    print(f"  P output   ={result:08X}")
    return result


def des_trace(block: bytes, key: bytes, decrypt: bool = False) -> bytes:
    """Print IP, all Feistel internals, swap and final permutation."""
    keys = des_key_schedule_trace(key)
    if decrypt:
        keys.reverse()
        print("decryption: round keys used K16..K1")
    value = int.from_bytes(block, "big")
    permuted = des.permute(value, des.IP, 64)
    left, right = permuted >> 32, permuted & 0xFFFFFFFF
    print(f"input={value:016X}")
    print(f"IP   ={permuted:016X}; L0={left:08X}; R0={right:08X}")
    for number, round_key in enumerate(keys, 1):
        print(f"\n-- DES round {number} --")
        f_value = _des_f_trace(right, round_key)
        new_left, new_right = right, left ^ f_value
        print(f"  new L=old R={new_left:08X}")
        print(f"  new R=old L xor F={left:08X} xor {f_value:08X}={new_right:08X}")
        left, right = new_left, new_right
    preoutput = (right << 32) | left
    result = des.permute(preoutput, des.FP, 64).to_bytes(8, "big")
    print(f"\nfinal swap R16||L16={preoutput:016X}")
    print(f"FP output={result.hex().upper()}")
    return result


def triple_des_trace(block: bytes, key1: bytes, key2: bytes,
                     key3: bytes | None = None) -> bytes:
    """Print EDE stages. Two-key 3DES uses K3=K1."""
    actual_key3 = key1 if key3 is None else key3
    print("3DES encryption is C=E_K3(D_K2(E_K1(P)))")
    stage1 = des.des_encrypt_block(block, key1)
    print(f"stage 1 E_K1: {block.hex()} -> {stage1.hex()}")
    stage2 = des.des_decrypt_block(stage1, key2)
    print(f"stage 2 D_K2: {stage1.hex()} -> {stage2.hex()}")
    stage3 = des.des_encrypt_block(stage2, actual_key3)
    print(f"stage 3 E_K3: {stage2.hex()} -> {stage3.hex()}")
    recovered2 = des.des_decrypt_block(stage3, actual_key3)
    recovered1 = des.des_encrypt_block(recovered2, key2)
    recovered = des.des_decrypt_block(recovered1, key1)
    print(f"reverse D_K3 -> E_K2 -> D_K1 = {recovered.hex()}")
    return stage3


def aes_cbc_trace(message: bytes, key: bytes, iv: bytes) -> bytes:
    """Trace PKCS#7 and CBC's XOR chain using the pure AES block function."""
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")
    padded = aes.pkcs7_pad(message)
    print(f"message={message!r}")
    print(f"padding length={padded[-1]}; padded={padded.hex()}")
    print(f"C0=IV={iv.hex()}")
    previous, blocks = iv, []
    for index in range(0, len(padded), 16):
        plain = padded[index:index + 16]
        mixed = aes.xor_bytes(plain, previous)
        encrypted = aes.aes_encrypt_block(mixed, key)
        number = index // 16 + 1
        print(f"block {number}: P={plain.hex()}")
        print(f"         P xor C{number - 1}={mixed.hex()}")
        print(f"         C{number}=AES(K,mixed)={encrypted.hex()}")
        blocks.append(encrypted)
        previous = encrypted
    result = b"".join(blocks)
    print("ciphertext=", result.hex())
    return result


def des_cbc_trace(message: bytes, key: bytes, iv: bytes) -> bytes:
    """Trace DES-CBC padding, XOR and ciphertext feedback block by block."""
    if len(iv) != 8:
        raise ValueError("DES-CBC IV must be 8 bytes")
    padded = aes.pkcs7_pad(message, 8)
    print(f"padding length={padded[-1]}; padded={padded.hex()}; C0=IV={iv.hex()}")
    previous, output = iv, []
    for offset in range(0, len(padded), 8):
        plain = padded[offset:offset + 8]
        mixed = bytes(left ^ right for left, right in zip(plain, previous))
        cipher = des.des_encrypt_block(mixed, key)
        number = offset // 8 + 1
        print(f"block {number}: P={plain.hex()}, P xor C{number-1}={mixed.hex()}, C={cipher.hex()}")
        output.append(cipher)
        previous = cipher
    result = b"".join(output)
    print("ciphertext:", result.hex())
    return result


def aes_ctr_trace(message: bytes, key: bytes, initial_counter: int = 0) -> bytes:
    """Trace CTR counters, encrypted counters and XOR. No padding is needed."""
    if not 0 <= initial_counter < 1 << 128:
        raise ValueError("counter must fit 128 bits")
    output = bytearray()
    for offset in range(0, len(message), 16):
        number = offset // 16
        block = message[offset:offset + 16]
        counter = (initial_counter + number) % (1 << 128)
        counter_block = counter.to_bytes(16, "big")
        keystream = aes.aes_encrypt_block(counter_block, key)
        cipher = bytes(left ^ right for left, right in zip(block, keystream))
        print(f"block {number}: counter={counter_block.hex()}")
        print(f"         AES(K,counter)={keystream.hex()}")
        print(f"         input={block.hex()} xor keystream prefix={keystream[:len(block)].hex()}")
        print(f"         output={cipher.hex()}")
        output.extend(cipher)
    print("CTR result:", output.hex())
    print("same operation decrypts: encrypting ciphertext with same counter restores plaintext")
    return bytes(output)


def demo() -> None:
    heading("LAB 2: AES-128 FULL TRACE")
    aes_trace(bytes.fromhex("00112233445566778899aabbccddeeff"),
              bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    heading("LAB 2: DES FULL TRACE")
    des_trace(bytes.fromhex("0123456789ABCDEF"),
              bytes.fromhex("133457799BBCDFF1"))
    heading("LAB 2: 3DES STAGES")
    triple_des_trace(b"12345678", b"12345678", b"ABCDEFGH")
    heading("LAB 2: AES-CBC CHAIN")
    aes_cbc_trace(b"two CBC blocks worth", bytes(range(16)), bytes(range(16, 32)))
    heading("LAB 2: DES-CBC CHAIN")
    des_cbc_trace(b"DES CBC example", b"12345678", b"87654321")
    heading("LAB 2: AES-CTR COUNTERS")
    aes_ctr_trace(b"CTR accepts partial final blocks", bytes(range(16)), 1)


if __name__ == "__main__":
    demo()
