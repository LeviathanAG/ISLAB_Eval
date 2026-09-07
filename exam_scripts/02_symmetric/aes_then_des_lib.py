from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

# MODIFY the message and keys. AES key=16/24/32 bytes; DES key=8 bytes.
message, aes_key, des_key = b'Mixed symmetric ciphers', b'A' * 16, b'D' * 8
# Encryption order: plaintext -> AES -> DES. Each ECB stage gets its own padding.
aes_output = AES.new(aes_key, AES.MODE_ECB).encrypt(pad(message, 16))
ciphertext = DES.new(des_key, DES.MODE_ECB).encrypt(pad(aes_output, 8))
# Decryption must reverse the order: DES -> AES.
aes_output = unpad(DES.new(des_key, DES.MODE_ECB).decrypt(ciphertext), 8)
plaintext = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(aes_output), 16)
print('ciphertext:', ciphertext.hex()); print('plaintext:', plaintext)
