from math import gcd

key, message = 15, 'I am learning information security'
if gcd(key, 26) != 1: raise ValueError('key must be coprime with 26')
clean = ''.join(c for c in message.upper() if c.isalpha())
ciphertext = ''.join(chr(((ord(c) - 65) * key) % 26 + 65) for c in clean)
plaintext = ''.join(chr(((ord(c) - 65) * pow(key, -1, 26)) % 26 + 65) for c in ciphertext)
print('ciphertext:', ciphertext); print('plaintext:', plaintext)
