from caesar import caesar

for shift in range(26): print(shift, caesar('KHOOR ZRUOG', -shift))
print('known plaintext CIW -> YES:', caesar('CIW', -4))
