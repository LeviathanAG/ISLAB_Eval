import time

def time_call(function, repeats=10):
    start = time.perf_counter()
    for _ in range(repeats): function()
    return (time.perf_counter() - start) / repeats

def hex_bytes(text):
    return bytes.fromhex(text.replace(' ', ''))

def show_round_trip(encrypt, decrypt, message):
    ciphertext = encrypt(message); plaintext = decrypt(ciphertext)
    print('ciphertext:', ciphertext); print('plaintext:', plaintext); assert plaintext == message

print('Copy time_call, hex_bytes, or show_round_trip into an exam answer.')
