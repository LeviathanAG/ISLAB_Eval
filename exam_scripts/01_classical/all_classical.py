"""Menu-driven copy of the complete Lab 1 classical-cipher toolkit."""
from math import gcd

ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def clean(text):
    return ''.join(c for c in text.upper() if c in ABC)


def inverse(a, m=26, backend='pure'):
    if backend == 'lib':
        from sympy import mod_inverse
        return int(mod_inverse(a, m))
    old, new, r, s = a % m, m, 1, 0
    while new:
        q = old // new
        old, new, r, s = new, old - q * new, s, r - q * s
    if old != 1:
        raise ValueError(f'{a} has no inverse modulo {m}')
    return r % m


def affine(text, a=1, b=0, decrypt=False, backend='pure', preserve=False):
    inv = inverse(a, 26, backend)  # Reject invalid keys even for encryption.
    if backend == 'lib' and not preserve:
        from sympy.crypto.crypto import encipher_affine, decipher_affine
        return (decipher_affine if decrypt else encipher_affine)(clean(text), (a % 26, b % 26))
    def letter(c):
        x = ord(c.upper()) - 65
        y = inv * (x - b) if decrypt else a * x + b
        out = ABC[y % 26]
        return out.lower() if preserve and c.islower() else out
    return ''.join(letter(c) if c.upper() in ABC else c for c in text) if preserve else ''.join(letter(c) for c in clean(text))


def vigenere(text, key, decrypt=False, autokey=False, backend='pure'):
    text, key = clean(text), clean(key)
    if not key:
        raise ValueError('Key must contain ASCII letters (numeric autokey 7 means H)')
    if backend == 'lib' and not autokey:
        from sympy.crypto.crypto import encipher_vigenere, decipher_vigenere
        return (decipher_vigenere if decrypt else encipher_vigenere)(text, key)
    stream, result = list(key), []
    for i, c in enumerate(text):
        k = ord(stream[i] if autokey else key[i % len(key)]) - 65
        out = ABC[(ord(c) - 65 + (-k if decrypt else k)) % 26]
        if backend == 'lib':
            from sympy.crypto.crypto import encipher_shift, decipher_shift
            out = (decipher_shift if decrypt else encipher_shift)(c, k)
        result.append(out)
        if autokey:
            stream.append(out if decrypt else c)
    return ''.join(result)


def playfair(text, key, decrypt=False, backend='pure'):
    square = ''.join(dict.fromkeys(clean(key).replace('J', 'I') + ABC.replace('J', '')))
    text = clean(text).replace('J', 'I')
    pairs = []
    if decrypt:
        if len(text) % 2:
            raise ValueError('Playfair ciphertext must have even length')
        pairs = [text[i:i+2] for i in range(0, len(text), 2)]
    else:
        i = 0
        while i < len(text):
            a = text[i]
            filler = 'Q' if a == 'X' else 'X'
            b = text[i+1] if i+1 < len(text) else filler
            if a == b:
                pairs.append(a + filler)
                i += 1
            else:
                pairs.append(a+b)
                i += 2
    matrix = None
    if backend == 'lib':
        from sympy import Matrix
        matrix = Matrix(5, 5, [ord(c) for c in square])
    out, shift = [], -1 if decrypt else 1
    for a, b in pairs:
        r, c = divmod(square.index(a), 5)
        s, d = divmod(square.index(b), 5)
        if r == s:
            c, d = (c+shift) % 5, (d+shift) % 5
        elif c == d:
            r, s = (r+shift) % 5, (s+shift) % 5
        else:
            c, d = d, c
        out += [chr(int(matrix[r,c])), chr(int(matrix[s,d]))] if matrix is not None else [square[5*r+c], square[5*s+d]]
    return ''.join(out)


def determinant(a):
    if not a:
        return 1
    return sum((-1)**j * a[0][j] * determinant([row[:j]+row[j+1:] for row in a[1:]]) for j in range(len(a)))


def matrix_inverse(a, backend='pure'):
    n = len(a)
    if not n or any(len(row) != n for row in a):
        raise ValueError('Hill key must be a nonempty square matrix')
    if backend == 'lib':
        from sympy import Matrix
        mat = Matrix(a)
        # Adjugate works over composite Z26 even when Gaussian pivots are nonunits.
        return [[int(v) % 26 for v in row] for row in (mat.adjugate()*inverse(int(mat.det()), 26, backend)).tolist()]
    d = inverse(determinant(a))
    return [[d * (-1)**(i+j) * determinant([row[:i]+row[i+1:] for k, row in enumerate(a) if k != j]) % 26 for j in range(n)] for i in range(n)]


def hill(text, key, decrypt=False, backend='pure'):
    inv = matrix_inverse(key, backend)
    text, n = clean(text), len(key)
    if decrypt and len(text) % n:
        raise ValueError('Ciphertext length must be a multiple of the matrix size')
    if not decrypt:
        text += 'X' * (-len(text) % n)
    key = inv if decrypt else key
    out = []
    for i in range(0, len(text), n):
        block = [ord(c)-65 for c in text[i:i+n]]
        if backend == 'lib':
            from sympy import Matrix
            out.extend(ABC[int(x) % 26] for x in Matrix(key)*Matrix(block))
        else:
            out.extend(ABC[sum(x*y for x, y in zip(row, block)) % 26] for row in key)
    return ''.join(out)


def permutation(text, key, decrypt=False):
    n = len(key)
    if not n or sorted(key) != list(range(n)):
        raise ValueError('Permutation must contain each zero-based index once')
    if decrypt and len(text) % n:
        raise ValueError('Ciphertext must contain complete permutation blocks')
    text += '' if decrypt else 'X' * (-len(text) % n)
    if decrypt:
        key = [key.index(i) for i in range(n)]
    return ''.join(text[i+j] for i in range(0, len(text), n) for j in key)


def infer_permutation(plain, cipher):
    plain, cipher = clean(plain), clean(cipher)
    if sorted(plain) != sorted(cipher):
        raise ValueError('Not a transposition: symbol counts differ (manual has I changed to L)')
    answers = []
    for n in range(1, len(plain)+1):
        if len(plain) % n or len(set(plain[:n])) != n:
            continue
        try:
            key = [plain[:n].index(c) for c in cipher[:n]]
            if permutation(plain, key) == cipher:
                answers.append(key)
        except ValueError:
            pass
    return answers


def rail(text, rails=3, decrypt=False):
    if rails < 1:
        raise ValueError('Rails must be positive')
    if rails == 1:
        return text
    path = [min(i % (2*rails-2), 2*rails-2-i % (2*rails-2)) for i in range(len(text))]
    order = sorted(range(len(text)), key=lambda i: path[i])
    if not decrypt:
        return ''.join(text[i] for i in order)
    result = ['']*len(text)
    for i, c in zip(order, text):
        result[i] = c
    return ''.join(result)


def columnar(text, key, decrypt=False):
    if not key:
        raise ValueError('Columnar key cannot be empty')
    order = sorted(range(len(key)), key=lambda i: (key[i], i))
    indices = [i for col in order for i in range(col, len(text), len(key))]
    if not decrypt:
        return ''.join(text[i] for i in indices)
    out = ['']*len(text)
    for i, c in zip(indices, text):
        out[i] = c
    return ''.join(out)


def candidates(cipher, known_plain='', known_cipher='', birthday=None, backend='pure'):
    if len(clean(known_plain)) != len(clean(known_cipher)):
        raise ValueError('Known plaintext and ciphertext lengths differ')
    pairs = [(a,b) for a in range(26) if gcd(a,26)==1 for b in range(26)]
    if birthday is not None:
        pairs = [(1,b) for b in sorted(range(26), key=lambda b: min((b-birthday)%26,(birthday-b)%26))]
    return [(a,b,affine(cipher,a,b,True,backend,preserve=True)) for a,b in pairs if affine(known_plain,a,b,backend=backend)==clean(known_cipher)]


def main():
    """Run the most useful Lab 1 examples without command-line options."""

    while True:
        print("\n=== Lab 1 classical ciphers ===")
        print("1. Additive  2. Multiplicative  3. Affine")
        print("4. Vigenere  5. Autokey  6. Playfair  7. Hill")
        print("8. Affine known-plaintext attack  0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        text = input("Message (Enter uses a sample): ") or "Information Security"
        try:
            if choice == "1": print(affine(text, b=20))
            elif choice == "2": print(affine(text, a=15))
            elif choice == "3": print(affine(text, a=15, b=20))
            elif choice == "4": print(vigenere(text, "dollars"))
            elif choice == "5": print(vigenere(text, "H", autokey=True))
            elif choice == "6": print(playfair(text, "GUIDANCE"))
            elif choice == "7": print(hill(text, [[3, 3], [2, 7]]))
            elif choice == "8": print(candidates(text, "AB", "GL"))
            else: print("Invalid choice.")
        except ValueError as exc:
            print(f"Could not run example: {exc}")


if __name__ == '__main__': main()
