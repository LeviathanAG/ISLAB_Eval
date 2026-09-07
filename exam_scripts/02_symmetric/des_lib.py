from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# MODIFY: DES keys are exactly 8 bytes. Hex key: bytes.fromhex('A1B2C3D4E5F60708').
key = b'A1B2C3D4'
# MODIFY: change plaintext here. DES has an 8-byte block size.
message = b'Confidential Data'
# MODIFY MODE: ECB needs no IV. For CBC use DES.MODE_CBC and an 8-byte iv.
ciphertext = DES.new(key, DES.MODE_ECB).encrypt(pad(message, 8))
print('ciphertext:', ciphertext.hex())
# Decryption repeats the same key, mode and IV (if the selected mode has one).
plaintext = unpad(DES.new(key, DES.MODE_ECB).decrypt(ciphertext), 8)
print('plaintext:', plaintext.decode())
