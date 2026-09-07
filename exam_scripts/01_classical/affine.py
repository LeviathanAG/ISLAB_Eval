from math import gcd

def affine(text, a, b, decrypt=False):
    if gcd(a, 26) != 1: raise ValueError('a must be coprime with 26')
    inverse = pow(a, -1, 26); output = ''
    for c in text.upper():
        if c.isalpha():
            x = ord(c) - 65; x = inverse * (x - b) if decrypt else a * x + b
            output += chr(x % 26 + 65)
    return output

message = 'I am learning information security'; ciphertext = affine(message, 15, 20)
print('ciphertext:', ciphertext); print('plaintext:', affine(ciphertext, 15, 20, True))
