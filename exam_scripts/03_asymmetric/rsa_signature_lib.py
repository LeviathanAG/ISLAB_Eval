from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

key, message = RSA.generate(2048), b'Approved document'; signature = pss.new(key).sign(SHA256.new(message))
pss.new(key.publickey()).verify(SHA256.new(message), signature)
print('signature valid:', signature.hex())
