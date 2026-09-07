from Crypto.Cipher import AES

# MODIFY block, but keep it exactly 16 bytes to show the repeated-block pattern.
block, key = b'YELLOW SUBMARINE', b'0' * 16
# ECB encrypts equal input blocks to equal output blocks under one key.
ciphertext = AES.new(key, AES.MODE_ECB).encrypt(block * 3)
print([ciphertext[i:i + 16].hex() for i in range(0, len(ciphertext), 16)])
print('Repeated plaintext blocks produce repeated ECB ciphertext blocks.')
