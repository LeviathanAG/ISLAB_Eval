from Crypto.Cipher import AES
from secrets import token_bytes

key, message = token_bytes(32), b'authenticated message'; cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(message); ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
try: AES.new(key, AES.MODE_GCM, nonce=cipher.nonce).decrypt_and_verify(ciphertext, tag)
except ValueError: print('Tampering correctly rejected')
