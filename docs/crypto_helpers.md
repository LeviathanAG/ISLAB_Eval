Help on module solved_pyqs.crypto_helpers in solved_pyqs:

NAME
    solved_pyqs.crypto_helpers - Small, readable cryptographic building blocks used by the solved PYQs.

DESCRIPTION
    This module intentionally keeps the examples self-contained.  It uses the
    ``cryptography`` package for AES and RSA, while Paillier and the educational
    ElGamal signature are implemented directly so that the homomorphic equations
    are visible in the source.

    The functions are educational examples for a lab, not a replacement for a
    reviewed production cryptographic protocol.  In particular, MD5 and the
    small ElGamal group used by the demos must not be used for real systems.

FUNCTIONS
    aes_cbc_decrypt(ciphertext: 'bytes', key: 'bytes', iv: 'bytes') -> 'bytes'
        Decrypt and unpad an AES-CBC ciphertext.

    aes_cbc_encrypt(plaintext: 'bytes', key: 'bytes') -> 'tuple[bytes, bytes]'
        Encrypt with AES-CBC and return ``(iv, ciphertext)``.

        AES-192 therefore requires a 24-byte key and AES-256 requires a 32-byte
        key.  A fresh random IV is generated for every encryption.

    b64_decode(value: 'str') -> 'bytes'
        Decode a base64 JSON field and raise a useful error for bad input.

    b64_encode(value: 'bytes') -> 'str'
        Encode bytes as text suitable for a JSON record.

    canonical_json(value: 'Any') -> 'bytes'
        Serialize a value deterministically before hashing or signing it.

    combine_threshold_shares(threshold: 'dict[str, Any]', first: 'int' = 0, second: 'int' = 1) -> 'tuple[int, int]'
        Combine two separate shares, rejecting a missing or duplicate share.

    elgamal_keygen(private: 'int | None' = None) -> 'dict[str, int]'
        Create an educational ElGamal signing keypair.

    elgamal_sign(message: 'bytes', private_key: 'dict[str, int]') -> 'tuple[int, int]'
        Return ``(r, s)`` for the textbook ElGamal signature equation.

    elgamal_verify(message: 'bytes', signature: 'Iterable[int]', public_key: 'dict[str, int]') -> 'bool'
        Verify ``g^H(m) = y^r r^s (mod p)`` without leaking exceptions.

    ensure_rsa_keypair(directory: 'Path', bits: 'int' = 2048)
        Load or create an RSA keypair in PEM files under ``directory``.

    generate_prime(bits: 'int') -> 'int'
        Generate an odd probable prime with the requested bit length.

    hex_dump(data: 'bytes', width: 'int' = 16) -> 'str'
        Return a conventional offset/hex/ascii dump for a byte string.

    is_probable_prime(number: 'int', rounds: 'int' = 24) -> 'bool'
        Miller-Rabin primality test suitable for lab-sized generated keys.

    load_json(path: 'Path', default: 'Any') -> 'Any'
        Load JSON, returning ``default`` when a new store does not exist.

    make_additive_threshold_shares(key: 'dict[str, int]', share_count: 'int' = 2) -> 'dict[str, Any]'
        Split Paillier's two private values into additive shares.

        This is a deliberately clear 2-of-2 teaching model: every share is needed
        to reconstruct ``lambda`` and ``mu``.  It demonstrates the access-control
        property requested by the e-voting question; production threshold Paillier
        should use a reviewed threshold cryptography implementation.

    make_password_record(password: 'str') -> 'dict[str, Any]'
        Create a salted PBKDF2-HMAC record for a local role password.

    paillier_add(left: 'int', right: 'int', public_key: 'dict[str, int]') -> 'int'
        Add two encrypted integers by multiplying ciphertexts modulo n².

    paillier_decrypt(ciphertext: 'int', key: 'dict[str, int]') -> 'int'
        Decrypt one Paillier ciphertext using its private key.

    paillier_decrypt_with_private_parts(ciphertext: 'int', public_key: 'dict[str, int]', private_lambda: 'int', private_mu: 'int') -> 'int'
        Decrypt with reconstructed threshold shares, without a full key dict.

    paillier_encrypt(message: 'int', public_key: 'dict[str, int]') -> 'int'
        Encrypt an integer using Paillier's additive homomorphism.

    paillier_generate(bits: 'int' = 256) -> 'dict[str, int]'
        Generate a Paillier keypair represented by JSON-friendly integers.

    paillier_public(key: 'dict[str, int]') -> 'dict[str, int]'
        Return only the public portion of a Paillier key.

    parse_timestamp(value: 'str') -> 'datetime'
        Parse the timestamp format emitted by :func:`utc_now`.

    rsa_decrypt(ciphertext: 'bytes', private_key) -> 'bytes'
        Decrypt an RSA-OAEP-SHA256 ciphertext.

    rsa_encrypt(plaintext: 'bytes', public_key) -> 'bytes'
        Encrypt a short key with RSA-OAEP-SHA256.

    rsa_sign(message: 'bytes', private_key) -> 'bytes'
        Sign bytes using RSA-PSS with SHA-256.

    rsa_verify(message: 'bytes', signature: 'bytes', public_key) -> 'bool'
        Return ``False`` instead of raising for an invalid RSA signature.

    save_json(path: 'Path', value: 'Any') -> 'None'
        Atomically save a JSON file so a partial write does not corrupt data.

    timestamp_token(timestamp: 'str', message_hash: 'str', secret: 'bytes') -> 'str'
        Create a trusted-authority MAC over a timestamp and ballot hash.

    utc_now() -> 'str'
        Return an ISO-8601 UTC timestamp with a trailing ``Z``.

    verify_password_record(password: 'str', record: 'dict[str, Any]') -> 'bool'
        Verify a role password with a constant-time digest comparison.

    verify_timestamp_token(timestamp: 'str', message_hash: 'str', token: 'str', secret: 'bytes') -> 'bool'
        Verify a timestamp token using constant-time comparison.

DATA
    ELGAMAL_G = 5
    ELGAMAL_P = 578960446186580977...8792003956564819949
    Iterable = typing.Iterable
        A generic version of collections.abc.Iterable.

FILE
    /home/hesa6004/IS_LAB_prac/ISLAB_Eval/solved_pyqs/crypto_helpers.py


