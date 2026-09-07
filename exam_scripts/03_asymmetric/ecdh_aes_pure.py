from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[2]))
import hybrid

key = hybrid.keygen('ecc', 'pure'); message = b'Secure Transactions'
packet = hybrid.encrypt(message, hybrid.public(key), 'pure')
print('packet bytes:', len(packet)); print('plaintext:', hybrid.decrypt(packet, key, 'pure'))
