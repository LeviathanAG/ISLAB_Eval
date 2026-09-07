from all_symmetric import crypt

# MODIFY: AES key is 16/24/32 bytes; IV is 16; this CTR nonce is 8.
key, iv, nonce = b'0' * 16, b'1' * 16, b'2' * 8
message = b'Cryptography Lab Exercise'  # MODIFY plaintext here.
# MODIFY: keep one mode, or add/remove names from this tuple.
for mode in ('ECB', 'CBC', 'CFB', 'OFB', 'CTR'):
    # CBC/CFB/OFB need an IV; CTR needs a nonce; ECB needs neither.
    options = {'iv': iv} if mode in ('CBC', 'CFB', 'OFB') else {'nonce': nonce} if mode == 'CTR' else {}
    # MODIFY algorithm to DES and use 8-byte key/IV if the question asks for DES.
    ciphertext = crypt(message, key, 'AES', mode, backend='pure', **options)
    # decrypt=True reverses the operation. All other arguments must match encryption.
    plaintext = crypt(ciphertext, key, 'AES', mode, decrypt=True, backend='pure', **options)
    print(mode, ciphertext.hex(), plaintext)
