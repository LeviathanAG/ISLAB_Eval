"""Run RSA-PSS, ElGamal, Schnorr and DSA sign/verify demonstrations."""
from signatures import *

MESSAGE = b"Approved document"
private, public = rsa_generate(2048)
signature = rsa_sign(MESSAGE, private)
print("RSA-PSS:", rsa_verify(MESSAGE, signature, public))

private, public = elgamal_keygen()
signature = elgamal_sign(MESSAGE, private)
print("ElGamal:", elgamal_verify(MESSAGE, signature, public))

private, public = schnorr_keygen()
signature = schnorr_sign(MESSAGE, private)
print("Schnorr:", schnorr_verify(MESSAGE, signature, public))

private, public = dsa_keygen()
signature = dsa_sign(MESSAGE, private)
print("DSA (DH-family math):", dsa_verify(MESSAGE, signature, public))
