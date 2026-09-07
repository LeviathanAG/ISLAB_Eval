def cube_root(number):
    low, high = 0, number
    while low + 1 < high:
        middle = (low + high) // 2
        if middle ** 3 <= number: low = middle
        else: high = middle
    return low

message, e, n = 42, 3, 999999999999999999999999
ciphertext = message ** e
print('ciphertext:', ciphertext); print('recovered:', cube_root(ciphertext))
print('This works because raw RSA had message^e smaller than n. OAEP prevents it.')
