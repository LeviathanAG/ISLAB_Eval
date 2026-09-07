from Crypto.PublicKey import ECC, RSA
from Crypto.Protocol.DH import key_agreement
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def kdf(secret): return SHA256.new(secret).digest()
alice_dh, bob_dh, alice_rsa = ECC.generate(curve='p256'), ECC.generate(curve='p256'), RSA.generate(2048)
transcript = alice_dh.public_key().export_key(format='DER') + bob_dh.public_key().export_key(format='DER')
signature = pss.new(alice_rsa).sign(SHA256.new(transcript))
pss.new(alice_rsa.publickey()).verify(SHA256.new(transcript), signature)
key = key_agreement(static_priv=alice_dh, static_pub=bob_dh.public_key(), kdf=kdf)
print('authenticated shared key:', key.hex())
