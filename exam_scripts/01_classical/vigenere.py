def vigenere(text, key, decrypt=False):
    text = ''.join(c for c in text.upper() if c.isalpha()); output = ''
    for i, c in enumerate(text):
        shift = ord(key[i % len(key)].upper()) - 65
        output += chr((ord(c) - 65 + (-shift if decrypt else shift)) % 26 + 65)
    return output

message, key = 'the house is being sold tonight', 'dollars'; ciphertext = vigenere(message, key)
print('ciphertext:', ciphertext); print('plaintext:', vigenere(ciphertext, key, True))
