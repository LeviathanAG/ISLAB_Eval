from all_symmetric import DES, pad, unpad

# MODIFY: DES key is exactly 8 bytes and DES block size is 8 bytes.
key, message = b'A1B2C3D4', b'Confidential Data'
des = DES(key)
# ECB block code needs padding. Use crypt(...) in aes_modes_pure.py for CBC/CFB/OFB.
padded = pad(message, 8)
ciphertext = b''.join(des.encrypt(padded[i:i + 8]) for i in range(0, len(padded), 8))
plaintext = unpad(b''.join(des.decrypt(ciphertext[i:i + 8]) for i in range(0, len(ciphertext), 8)), 8)
print('ciphertext:', ciphertext.hex()); print('plaintext:', plaintext)
