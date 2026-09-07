from Crypto.Cipher import AES
from secrets import token_bytes
from pathlib import Path

# MODIFY all three file names. Remove source.write_text(...) when input.txt already exists.
source, encrypted_file, decrypted_file = Path('input.txt'), Path('encrypted.bin'), Path('decrypted.txt')
source.write_text('Change input.txt or replace this line with your file.')
# MODIFY 32 to 16/24/32 for AES-128/192/256. Store this key securely.
key = token_bytes(32)
# GCM is used because it detects accidental or malicious changes to the file.
cipher = AES.new(key, AES.MODE_GCM); ciphertext, tag = cipher.encrypt_and_digest(source.read_bytes())
# File layout: 16-byte nonce || 16-byte tag || remaining ciphertext.
encrypted_file.write_bytes(cipher.nonce + tag + ciphertext)
data = encrypted_file.read_bytes()
plaintext = AES.new(key, AES.MODE_GCM, nonce=data[:16]).decrypt_and_verify(data[32:], data[16:32])
decrypted_file.write_bytes(plaintext); print('key:', key.hex(), 'plaintext:', plaintext.decode())
