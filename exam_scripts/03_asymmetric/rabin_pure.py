p, q, message = 499, 547, 42; n = p * q; ciphertext = message * message % n
mp, mq = pow(ciphertext, (p + 1) // 4, p), pow(ciphertext, (q + 1) // 4, q)
roots = {(a * q * pow(q, -1, p) + b * p * pow(p, -1, q)) % n for a in (mp, -mp) for b in (mq, -mq)}
print('ciphertext:', ciphertext); print('four roots:', sorted(roots)); print('original is present:', message in roots)
