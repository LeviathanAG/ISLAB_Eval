"""2x2 Hill cipher - standalone.

For column vector P=[p1,p2]^T, encryption is C=K*P mod 26.
K must be invertible modulo 26: gcd(det(K),26)=1.  For
K=[[a,b],[c,d]], K^-1=det(K)^-1 * [[d,-b],[-c,a]] mod 26.
"""
from math import gcd


def inverse_2x2(key: list[list[int]]) -> list[list[int]]:
    a, b = key[0]
    c, d = key[1]
    determinant = (a*d - b*c) % 26
    if gcd(determinant, 26) != 1:
        raise ValueError("determinant must be coprime to 26")
    inverse_determinant = pow(determinant, -1, 26)
    return [[d*inverse_determinant % 26, -b*inverse_determinant % 26],
            [-c*inverse_determinant % 26, a*inverse_determinant % 26]]


def hill(text: str, key: list[list[int]], decrypt: bool = False) -> str:
    text = "".join(c for c in text.upper() if "A" <= c <= "Z")
    if len(text) % 2:
        text += "X"
    matrix = inverse_2x2(key) if decrypt else key
    result = []
    for index in range(0, len(text), 2):
        p0, p1 = ord(text[index])-65, ord(text[index+1])-65
        result.append(chr(65 + (matrix[0][0]*p0 + matrix[0][1]*p1) % 26))
        result.append(chr(65 + (matrix[1][0]*p0 + matrix[1][1]*p1) % 26))
    return "".join(result)


if __name__ == "__main__":
    key = [[3, 3], [2, 7]]
    encrypted = hill("We live in an insecure world", key)
    print("ciphertext:", encrypted)
    print("plaintext :", hill(encrypted, key, decrypt=True))

