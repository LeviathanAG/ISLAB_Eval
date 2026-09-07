def autokey(text, first_key, decrypt=False):
    text = ''.join(c for c in text.upper() if c.isalpha()); stream = [first_key]; output = ''
    for i, c in enumerate(text):
        shift = stream[i]; value = (ord(c) - 65 - shift) % 26 if decrypt else (ord(c) - 65 + shift) % 26
        output += chr(value + 65); stream.append(value if decrypt else ord(c) - 65)
    return output

message = 'the house is being sold tonight'; ciphertext = autokey(message, 7)
print('ciphertext:', ciphertext); print('plaintext:', autokey(ciphertext, 7, True))
