"""Recover RSA private key when p and q are small or too close.

Trial division works for tiny primes.  Fermat factorization is fast when
p and q are close because n=pq=a^2-b^2=(a-b)(a+b).  After factoring n, compute
phi=(p-1)(q-1) and d=e^-1 mod phi.  Mitigation: generate independent,
unpredictable, adequately sized primes with a vetted RSA library (2048+ bits),
validate keys, and rotate any exposed key.
"""
from math import isqrt


def fermat_factor(n: int):
    a = isqrt(n)
    if a*a < n:
        a += 1
    while True:
        b_squared = a*a - n
        b = isqrt(b_squared)
        if b*b == b_squared:
            return a-b, a+b
        a += 1


def recover_private_exponent(n: int, e: int):
    p, q = fermat_factor(n)
    d = pow(e, -1, (p-1)*(q-1))
    return p, q, d


if __name__ == "__main__":
    p, q, e = 1009, 1013, 65537
    recovered = recover_private_exponent(p*q, e)
    print("recovered p,q,d:", recovered)

