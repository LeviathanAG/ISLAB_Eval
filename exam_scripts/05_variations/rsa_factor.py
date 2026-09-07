from math import gcd

n1, n2 = 1009 * 1013, 1009 * 1019
shared = gcd(n1, n2)
print('shared prime:', shared); print('factors:', (shared, n1 // shared), (shared, n2 // shared))
