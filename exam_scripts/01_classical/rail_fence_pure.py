def rail_fence(text, rails, decrypt=False):
    path = [min(i % (2 * rails - 2), 2 * rails - 2 - i % (2 * rails - 2)) for i in range(len(text))]
    order = sorted(range(len(text)), key=lambda i: path[i])
    if not decrypt: return ''.join(text[i] for i in order)
    result = [''] * len(text)
    for i, c in zip(order, text): result[i] = c
    return ''.join(result)

message = 'WEAREDISCOVEREDFLEEATONCE'; ciphertext = rail_fence(message, 3)
print('ciphertext:', ciphertext); print('plaintext:', rail_fence(ciphertext, 3, True))
