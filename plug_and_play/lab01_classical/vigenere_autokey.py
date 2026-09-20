"""Vigenere and plaintext-autokey ciphers - standalone.

Vigenere: C_i=(P_i+K_(i mod key_length)) mod 26.
Autokey: the stream starts with the supplied key, then continues with plaintext
letters.  A numeric key 7 means letter H because A=0 and H=7.
"""


def clean(text: str) -> str:
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def vigenere_encrypt(text: str, keyword: str) -> str:
    text, keyword = clean(text), clean(keyword)
    if not keyword:
        raise ValueError("keyword must contain letters")
    return "".join(chr(65 + (ord(c)-65 + ord(keyword[i % len(keyword)])-65) % 26)
                   for i, c in enumerate(text))


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    ciphertext, keyword = clean(ciphertext), clean(keyword)
    if not keyword:
        raise ValueError("keyword must contain letters")
    return "".join(chr(65 + (ord(c)-65 - (ord(keyword[i % len(keyword)])-65)) % 26)
                   for i, c in enumerate(ciphertext))


def autokey_encrypt(text: str, initial_key: str | int) -> str:
    text = clean(text)
    key = chr(65 + initial_key % 26) if isinstance(initial_key, int) else clean(initial_key)
    stream = key + text  # only the first len(text) symbols are used
    return "".join(chr(65 + (ord(c)-65 + ord(stream[i])-65) % 26)
                   for i, c in enumerate(text))


def autokey_decrypt(ciphertext: str, initial_key: str | int) -> str:
    ciphertext = clean(ciphertext)
    stream = list(chr(65 + initial_key % 26) if isinstance(initial_key, int) else clean(initial_key))
    plaintext = []
    for i, character in enumerate(ciphertext):
        decoded = chr(65 + (ord(character)-65 - (ord(stream[i])-65)) % 26)
        plaintext.append(decoded)
        stream.append(decoded)  # recovered plaintext extends the key stream
    return "".join(plaintext)


if __name__ == "__main__":
    message = "the house is being sold tonight"
    c1 = vigenere_encrypt(message, "dollars")
    c2 = autokey_encrypt(message, 7)
    print(c1, vigenere_decrypt(c1, "dollars"))
    print(c2, autokey_decrypt(c2, 7))

