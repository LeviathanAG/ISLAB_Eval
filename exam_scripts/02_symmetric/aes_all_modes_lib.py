from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# MODIFY these four values. AES keys: 16/24/32 bytes. AES IV: 16 bytes.
# CTR nonce must be unique for this key; 8 bytes leaves 8 bytes for its counter.
key = b'0' * 16
iv = b'1' * 16
nonce = b'2' * 8
message = b'Cryptography Lab Exercise'

# ECB takes no IV. CBC takes `iv`. Both work on full blocks, so use pad/unpad.
for name, mode, extra in [('ECB', AES.MODE_ECB, {}), ('CBC', AES.MODE_CBC, {'iv': iv})]:
    ciphertext = AES.new(key, mode, **extra).encrypt(pad(message, 16))
    plaintext = unpad(AES.new(key, mode, **extra).decrypt(ciphertext), 16)
    print(name, ciphertext.hex(), plaintext)

# CFB/OFB/CTR work like stream ciphers here, so they do not need padding.
# MODIFY: keep only the tuple for the mode named by the question.
for name, mode, extra in [('CFB', AES.MODE_CFB, {'iv': iv}), ('OFB', AES.MODE_OFB, {'iv': iv}), ('CTR', AES.MODE_CTR, {'nonce': nonce})]:
    ciphertext = AES.new(key, mode, **extra).encrypt(message)
    plaintext = AES.new(key, mode, **extra).decrypt(ciphertext)
    print(name, ciphertext.hex(), plaintext)
