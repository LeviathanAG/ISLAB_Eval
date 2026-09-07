import secrets
p, g = 23, 5; a, b = secrets.randbelow(p - 2) + 1, secrets.randbelow(p - 2) + 1
A, B = pow(g, a, p), pow(g, b, p); alice, bob = pow(B, a, p), pow(A, b, p)
print('public values:', A, B, 'shared:', alice); assert alice == bob
