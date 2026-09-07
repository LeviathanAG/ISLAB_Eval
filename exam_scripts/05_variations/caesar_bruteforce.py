from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / '01_classical'))
from caesar import caesar

ciphertext = 'KHOOR ZRUOG'
for shift in range(26): print(shift, caesar(ciphertext, -shift))
