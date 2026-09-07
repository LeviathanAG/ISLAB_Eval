import secrets
p, g, x, message = 7919, 2, 2999, 65; h = pow(g, x, p); k = secrets.randbelow(p - 2) + 1
c1, c2 = pow(g, k, p), message * pow(h, k, p) % p
print('public:', (p, g, h), 'ciphertext:', (c1, c2)); print('plaintext:', c2 * pow(pow(c1, x, p), -1, p) % p)
