from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from secrets import token_bytes

rsa, message = RSA.generate(2048), b'Large secret document'; aes_key = token_bytes(32)
aes = AES.new(aes_key, AES.MODE_GCM); ciphertext, tag = aes.encrypt_and_digest(message)
wrapped_key = PKCS1_OAEP.new(rsa.publickey()).encrypt(aes_key)
recovered_key = PKCS1_OAEP.new(rsa).decrypt(wrapped_key)
plaintext = AES.new(recovered_key, AES.MODE_GCM, nonce=aes.nonce).decrypt_and_verify(ciphertext, tag)
print('wrapped AES key:', wrapped_key.hex()); print('plaintext:', plaintext)
