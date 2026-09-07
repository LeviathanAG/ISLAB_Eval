from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

sender, receiver, message = RSA.generate(2048), RSA.generate(2048), b'Finance report'
ciphertext = PKCS1_OAEP.new(receiver.publickey()).encrypt(message)
signature = pss.new(sender).sign(SHA256.new(ciphertext))
pss.new(sender.publickey()).verify(SHA256.new(ciphertext), signature)
print('signature valid; plaintext:', PKCS1_OAEP.new(receiver).decrypt(ciphertext))
