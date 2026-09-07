def letters(text): return ''.join(c for c in text.upper() if c.isalpha())
def affine(text, a, b, decrypt=False):
    inverse = pow(a, -1, 26)
    return ''.join(chr(((inverse * (ord(c) - 65 - b) if decrypt else a * (ord(c) - 65) + b) % 26) + 65) for c in letters(text))
def vigenere(text, key, decrypt=False):
    return ''.join(chr((ord(c) - 65 + (-1 if decrypt else 1) * (ord(key[i % len(key)]) - 65)) % 26 + 65) for i, c in enumerate(letters(text)))
def reverse_blocks(text, size): return ''.join(text[i:i + size][::-1] for i in range(0, len(text), size))

message = letters('Mix and match classical ciphers')
ciphertext = reverse_blocks(vigenere(affine(message, 15, 20), 'KEY'), 4)
plaintext = affine(vigenere(reverse_blocks(ciphertext, 4), 'KEY', True), 15, 20, True)
print('ciphertext:', ciphertext); print('plaintext:', plaintext)
