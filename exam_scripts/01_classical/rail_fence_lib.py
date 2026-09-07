from sympy.crypto.crypto import encipher_railfence, decipher_railfence

message, rails = 'WEAREDISCOVEREDFLEEATONCE', 3
ciphertext = encipher_railfence(message, rails)
print('ciphertext:', ciphertext); print('plaintext:', decipher_railfence(ciphertext, rails))
