from sympy.crypto.crypto import encipher_affine, decipher_affine

message, key = 'I am learning information security', (15, 20)
ciphertext = encipher_affine(message, key)
print('ciphertext:', ciphertext); print('plaintext:', decipher_affine(ciphertext, key))
