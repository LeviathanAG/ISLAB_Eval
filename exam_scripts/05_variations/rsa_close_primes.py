from math import isqrt

n = 1009 * 1013; a = isqrt(n)
if a * a < n: a += 1
while not isqrt(a * a - n) ** 2 == a * a - n: a += 1
b = isqrt(a * a - n)
print('factors:', a - b, a + b)
