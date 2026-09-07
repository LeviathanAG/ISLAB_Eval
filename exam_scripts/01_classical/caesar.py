ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def caesar(text, shift):
    return ''.join(ALPHABET[(ALPHABET.index(c) + shift) % 26] if c in ALPHABET else c for c in text.upper())

message = 'I am learning information security'
ciphertext = caesar(message, 20)
print('ciphertext:', ciphertext); print('plaintext:', caesar(ciphertext, -20))
