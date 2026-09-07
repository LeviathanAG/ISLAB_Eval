def columnar(text, key, decrypt=False):
    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    positions = [i for column in order for i in range(column, len(text), len(key))]
    if not decrypt: return ''.join(text[i] for i in positions)
    result = [''] * len(text)
    for i, c in zip(positions, text): result[i] = c
    return ''.join(result)

message, key = 'WEAREDISCOVEREDFLEEATONCE', 'ZEBRA'; ciphertext = columnar(message, key)
print('ciphertext:', ciphertext); print('plaintext:', columnar(ciphertext, key, True))
