from Crypto.Cipher import AES

key, nonce = b'0' * 16, b'1' * 8
first, second = b'known message 12', b'secret message 3'
def encrypt(message): return AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(message)
c1, c2 = encrypt(first), encrypt(second)
print('recovered second:', bytes(a ^ b ^ c for a, b, c in zip(c1, c2, first)))
print('Lesson: never reuse a CTR nonce with the same key.')
