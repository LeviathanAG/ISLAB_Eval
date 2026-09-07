from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# MODIFY plaintext here. AES block size remains 16 bytes for every key size.
message = b'Encryption Strength'
# MODIFY: keep one size: 16=AES-128, 24=AES-192, 32=AES-256.
for size in (16, 24, 32):
    key = b'K' * size  # Replace with the exact key given in the question.
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(message, 16))
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), 16)
    print('AES', size * 8, ciphertext.hex(), plaintext)
