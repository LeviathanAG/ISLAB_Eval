"""Lab 6 signature traces with every educational equation printed."""
from __future__ import annotations

import hashlib
from math import gcd

from trace_utils import heading, load_module


modern = load_module(
    "trace_modern_signatures", "plug_and_play/lab06_signatures/modern_signatures.py"
)


def _hash_mod(message: bytes, modulus: int) -> tuple[int, int]:
    full = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return full, full % modulus


def elgamal_signature_trace(message: bytes, p: int = 467, g: int = 2,
                             private: int = 127, nonce: int = 53):
    """Trace ElGamal signing. Fixed nonce is strictly for reproducible paper math."""
    if gcd(nonce, p - 1) != 1:
        raise ValueError("nonce k must be coprime to p-1")
    public = pow(g, private, p)
    full_hash, reduced_hash = _hash_mod(message, p - 1)
    r = pow(g, nonce, p)
    inverse = pow(nonce, -1, p - 1)
    s = inverse * (reduced_hash - private * r) % (p - 1)
    left = pow(g, reduced_hash, p)
    yr = pow(public, r, p)
    rs = pow(r, s, p)
    right = yr * rs % p
    print(f"message={message!r}; SHA-256={full_hash:064x}")
    print(f"H=hash mod (p-1)={reduced_hash}")
    print(f"p={p}, g={g}, private x={private}, public y=g^x mod p={public}")
    print(f"nonce k={nonce}; gcd(k,p-1)={gcd(nonce,p-1)}; k^-1 mod(p-1)={inverse}")
    print(f"r=g^k mod p={r}")
    print(f"s=k^-1(H-xr) mod(p-1)={inverse}*({reduced_hash}-{private}*{r}) mod {p-1}={s}")
    print(f"signature=(r={r}, s={s})")
    print(f"verify left =g^H mod p={left}")
    print(f"verify right=y^r*r^s mod p=({yr}*{rs}) mod {p}={right}")
    print("valid:", left == right)
    return r, s


def schnorr_signature_trace(message: bytes, p: int = 23, q: int = 11,
                            g: int = 2, private: int = 7, nonce: int = 4):
    """Trace the same Schnorr convention used by the repository."""
    public = pow(g, private, p)
    commitment = pow(g, nonce, p)
    width = (p.bit_length() + 7) // 8
    hash_input = commitment.to_bytes(width, "big") + message
    full_hash, challenge = _hash_mod(hash_input, q)
    response = (nonce + challenge * private) % q
    left = pow(g, response, p)
    ye = pow(public, challenge, p)
    right = commitment * ye % p
    print(f"group p={p}, subgroup q={q}, g={g}; q|(p-1)={(p-1)%q==0}; g^q mod p={pow(g,q,p)}")
    print(f"private x={private}; public y=g^x mod p={public}")
    print(f"nonce k={nonce}; commitment R=g^k mod p={commitment}")
    print(f"hash input=R_bytes||message={hash_input.hex()}")
    print(f"SHA-256={full_hash:064x}; challenge e=hash mod q={challenge}")
    print(f"response s=(k+e*x) mod q=({nonce}+{challenge}*{private}) mod {q}={response}")
    print(f"signature=(R={commitment},s={response})")
    print(f"verify left =g^s mod p={left}")
    print(f"verify right=R*y^e mod p={commitment}*{ye} mod {p}={right}")
    print("valid:", left == right)
    return commitment, response


def dsa_signature_trace(message: bytes, p: int = 23, q: int = 11,
                        g: int = 2, private: int = 7, nonce: int = 4):
    """Print DSA generation and verification values w,u1,u2,v."""
    if not 1 <= nonce < q:
        raise ValueError("nonce must be in 1..q-1")
    public = pow(g, private, p)
    full_hash, reduced_hash = _hash_mod(message, q)
    r = pow(g, nonce, p) % q
    inverse_nonce = pow(nonce, -1, q)
    s = inverse_nonce * (reduced_hash + private * r) % q
    inverse_s = pow(s, -1, q)
    u1 = reduced_hash * inverse_s % q
    u2 = r * inverse_s % q
    first = pow(g, u1, p)
    second = pow(public, u2, p)
    v = first * second % p % q
    print(f"p={p}, q={q}, g={g}, private x={private}, public y={public}")
    print(f"SHA-256(message)={full_hash:064x}; H mod q={reduced_hash}")
    print(f"nonce k={nonce}; k^-1 mod q={inverse_nonce}")
    print(f"r=(g^k mod p) mod q=({pow(g,nonce,p)}) mod {q}={r}")
    print(f"s=k^-1(H+x*r) mod q={inverse_nonce}*({reduced_hash}+{private}*{r}) mod {q}={s}")
    print(f"signature=(r={r},s={s})")
    print(f"verification w=s^-1 mod q={inverse_s}")
    print(f"u1=H*w mod q={u1}; u2=r*w mod q={u2}")
    print(f"g^u1 mod p={first}; y^u2 mod p={second}")
    print(f"v=((g^u1*y^u2 mod p) mod q)={v}; compare r={r}; valid={v==r}")
    return r, s


def rsa_signature_trace(message: bytes) -> bytes:
    """Print RSA-PSS inputs and observable outputs; padding randomness is internal."""
    private, public = modern.generate_rsa()
    digest = hashlib.sha256(message).digest()
    numbers = public.public_numbers()
    print(f"message={message!r}; length={len(message)} bytes")
    print("SHA-256(message)=", digest.hex())
    print(f"RSA modulus bits={public.key_size}; public e={numbers.e}")
    print("PSS parameters: MGF1-SHA256, SHA-256, salt length=digest length=32")
    signature = modern.rsa_pss_sign(message, private)
    print(f"signature length={len(signature)} bytes")
    print("signature hex=", signature.hex())
    print("verify original:", modern.rsa_pss_verify(message, signature, public))
    print("verify changed :", modern.rsa_pss_verify(message + b"!", signature, public))
    return signature


def modern_signature_trace(message: bytes) -> None:
    """Show structure, sizes and verification for DSA, ECDSA and Ed25519."""
    from cryptography.hazmat.primitives.asymmetric import utils

    cases = (
        ("DSA-2048/SHA-256", modern.generate_dsa, modern.dsa_sign, modern.dsa_verify, True),
        ("ECDSA-P256/SHA-256", modern.generate_ecdsa, modern.ecdsa_sign, modern.ecdsa_verify, True),
        ("Ed25519", modern.generate_ed25519, modern.ed25519_sign, modern.ed25519_verify, False),
    )
    for name, keygen, signer, verifier, is_der in cases:
        print(f"\n-- {name} --")
        private, public = keygen()
        signature = signer(message, private)
        print("message SHA-256 (display/reference):", hashlib.sha256(message).hexdigest())
        print(f"signature length={len(signature)} bytes; hex={signature.hex()}")
        if is_der:
            r, s = utils.decode_dss_signature(signature)
            print(f"DER decoded r={r}")
            print(f"DER decoded s={s}")
        else:
            print("Ed25519 encoding is fixed 64 bytes; do not DER-decode as (r,s)")
        print("original verifies:", verifier(message, signature, public))
        print("tampered verifies:", verifier(message + b"!", signature, public))


def signed_socket_frame_trace(message: bytes) -> bytes:
    """Print the fields and framing for the RSA-PSS client/server exercise."""
    private, public = modern.generate_rsa()
    signature = modern.rsa_pss_sign(message, private)
    message_length = len(message).to_bytes(4, "big")
    signature_length = len(signature).to_bytes(4, "big")
    frame = message_length + message + signature_length + signature
    print(f"message length={len(message)} -> {message_length.hex()}")
    print(f"message={message.hex()}")
    print(f"signature length={len(signature)} -> {signature_length.hex()}")
    print(f"signature={signature.hex()}")
    print("wire=msg_len||message||sig_len||signature")
    print(f"total frame bytes={len(frame)}")
    print("server reads exact fields, hashes exact message bytes, then verifies with public key")
    print("verification:", modern.rsa_pss_verify(message, signature, public))
    return frame


def demo() -> None:
    heading("LAB 6: ELGAMAL SIGNATURE")
    elgamal_signature_trace(b"exam")
    heading("LAB 6: SCHNORR SIGNATURE")
    schnorr_signature_trace(b"exam")
    heading("LAB 6: DSA SIGNATURE")
    dsa_signature_trace(b"exam")
    heading("LAB 6: RSA-PSS")
    rsa_signature_trace(b"exam")
    heading("LAB 6: MODERN SIGNATURE STRUCTURES")
    modern_signature_trace(b"exam")
    heading("LAB 6: SIGNED SOCKET FRAME")
    signed_socket_frame_trace(b"client message")


if __name__ == "__main__":
    demo()
