from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048); message = b'Asymmetric Encryption'; ciphertext = PKCS1_OAEP.new(key.publickey()).encrypt(message)
print('ciphertext:', ciphertext.hex()); print('plaintext:', PKCS1_OAEP.new(key).decrypt(ciphertext).decode())
