import hashlib, secrets

password, salt = b'exam-password', secrets.token_bytes(16)
key = hashlib.pbkdf2_hmac('sha256', password, salt, 600000)
print('salt:', salt.hex()); print('derived key:', key.hex())
