def reverse_blocks(text, size): return ''.join(text[i:i + size][::-1] for i in range(0, len(text), size))

message = 'WEAREDISCOVEREDFLEEATONCE'
ciphertext = reverse_blocks(reverse_blocks(message, 4), 5)
plaintext = reverse_blocks(reverse_blocks(ciphertext, 5), 4)
print('ciphertext:', ciphertext); print('plaintext:', plaintext)
