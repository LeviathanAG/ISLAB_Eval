p, g, x, k = 7919, 2, 2999, 101
h, known, secret = pow(g, x, p), 65, 90; mask = pow(h, k, p)
known_cipher, secret_cipher = known * mask % p, secret * mask % p
recovered = secret_cipher * pow(known_cipher, -1, p) * known % p
print('recovered secret:', recovered); print('Never reuse ElGamal k.')
