from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[2]))
from public_key import rsa_key, sign, verify

key, message = rsa_key(1024), b'Approved document'; signature = sign(message, key)
print('valid:', verify(message, signature, key)); print('changed document valid:', verify(message + b'!', signature, key))
