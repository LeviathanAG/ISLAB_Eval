from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# MODIFY: 3DES accepts 16 or 24 bytes. This example uses three distinct 8-byte keys.
key = DES3.adjust_key_parity(bytes.fromhex('0123456789ABCDEFFEDCBA987654321089ABCDEF01234567'))
message = b'Classified Text'  # MODIFY plaintext here.
# MODIFY MODE: for CBC use DES3.MODE_CBC and pass an 8-byte iv to both new() calls.
ciphertext = DES3.new(key, DES3.MODE_ECB).encrypt(pad(message, 8))
plaintext = unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ciphertext), 8)
print('ciphertext:', ciphertext.hex()); print('plaintext:', plaintext)
