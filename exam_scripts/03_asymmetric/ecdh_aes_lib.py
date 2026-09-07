from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def kdf(secret): return SHA256.new(secret).digest()
alice, bob = ECC.generate(curve='p256'), ECC.generate(curve='p256')
alice_key = key_agreement(static_priv=alice, static_pub=bob.public_key(), kdf=kdf)
bob_key = key_agreement(static_priv=bob, static_pub=alice.public_key(), kdf=kdf)
cipher = AES.new(alice_key, AES.MODE_GCM); ciphertext, tag = cipher.encrypt_and_digest(b'Secure Transactions')
plaintext = AES.new(bob_key, AES.MODE_GCM, nonce=cipher.nonce).decrypt_and_verify(ciphertext, tag)
print('ciphertext:', ciphertext.hex()); print('plaintext:', plaintext)
