from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# MODIFY: AES keys are exactly 16/24/32 bytes for AES-128/192/256.
key = b'0123456789ABCDEF'
# MODIFY: Prefix text with b, or use bytes.fromhex(...) for hexadecimal input.
message = b'Sensitive Information'
# MODIFY: CBC requires a 16-byte IV. Use the same IV to decrypt this ciphertext.
iv = b'1234567890ABCDEF'

# MODIFY MODE: replace MODE_CBC and its `iv` in both encryption and decryption.
# See aes_all_modes_lib.py for the correct arguments for every AES mode.
ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(message, 16))
print('ciphertext:', ciphertext.hex())
# CBC and ECB need PKCS#7 pad before encryption and unpad after decryption.
print('plaintext:', unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16).decode())
