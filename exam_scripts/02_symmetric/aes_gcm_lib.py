from Crypto.Cipher import AES
from secrets import token_bytes

# MODIFY: 16/24/32 gives AES-128/192/256. token_bytes makes a random key.
key = token_bytes(32)
message = b'Authenticated secret'  # MODIFY plaintext here.
# GCM creates a nonce and an authentication tag. Save both with ciphertext.
encryptor = AES.new(key, AES.MODE_GCM)
ciphertext, tag = encryptor.encrypt_and_digest(message)
# Decryption must receive the same key, nonce, ciphertext and tag.
decryptor = AES.new(key, AES.MODE_GCM, nonce=encryptor.nonce)
print('nonce:', encryptor.nonce.hex(), 'ciphertext:', ciphertext.hex(), 'tag:', tag.hex())
print('plaintext:', decryptor.decrypt_and_verify(ciphertext, tag))
