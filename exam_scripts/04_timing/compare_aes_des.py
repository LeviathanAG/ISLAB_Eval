from time_it import time_call
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad

# MODIFY the message. Both algorithms must process the same plaintext.
message = b'Performance Testing of Encryption Algorithms'
# Padding uses block size: AES=16 bytes, DES=8 bytes.
aes_data, des_data = pad(message, 16), pad(message, 8)
# MODIFY b'0'*16 to 24 or 32 bytes for AES-192/AES-256.
# time_call repeats ten times by default; pass repeats=1000 for steadier results.
print('AES seconds:', time_call(lambda: AES.new(b'0' * 16, AES.MODE_ECB).encrypt(aes_data)))
print('DES seconds:', time_call(lambda: DES.new(b'0' * 8, DES.MODE_ECB).encrypt(des_data)))
