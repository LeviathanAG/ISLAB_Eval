from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256

def kdf(secret): return SHA256.new(secret).digest()
alice, bob = ECC.generate(curve='p256'), ECC.generate(curve='p256')
alice_secret = key_agreement(static_priv=alice, static_pub=bob.public_key(), kdf=kdf)
bob_secret = key_agreement(static_priv=bob, static_pub=alice.public_key(), kdf=kdf)
print('shared key:', alice_secret.hex()); assert alice_secret == bob_secret
