from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

sender, receiver, message = RSA.generate(1024), RSA.generate(2048), b'Finance report'
signature = pss.new(sender).sign(SHA256.new(message))
packet = PKCS1_OAEP.new(receiver.publickey()).encrypt(message + signature)
recovered = PKCS1_OAEP.new(receiver).decrypt(packet); size = sender.size_in_bytes(); text, signature = recovered[:-size], recovered[-size:]
pss.new(sender.publickey()).verify(SHA256.new(text), signature)
print('decrypted and signature valid:', text)
