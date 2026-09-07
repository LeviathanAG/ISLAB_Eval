from sympy.crypto.crypto import encipher_affine, decipher_affine, encipher_vigenere, decipher_vigenere

message, affine_key, word = 'MIXANDMATCHCLASSICALCIPHERS', (15, 20), 'KEY'
ciphertext = encipher_vigenere(encipher_affine(message, affine_key), word)
plaintext = decipher_affine(decipher_vigenere(ciphertext, word), affine_key)
print('ciphertext:', ciphertext); print('plaintext:', plaintext)
