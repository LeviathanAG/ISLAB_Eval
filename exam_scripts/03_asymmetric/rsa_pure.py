p, q, e, message = 61, 53, 17, 65
n = p * q; phi = (p - 1) * (q - 1); d = pow(e, -1, phi)
ciphertext = pow(message, e, n)
print('public:', (n, e), 'private:', (n, d)); print('ciphertext:', ciphertext); print('plaintext:', pow(ciphertext, d, n))
