"""Readable DES, 3DES, and AES implementations with common modes."""


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gf(a, b):
    result = 0
    while b:
        if b & 1: result ^= a
        a = (a << 1) ^ (0x11b if a & 128 else 0)
        b >>= 1
    return result


def gf_power(a, n):
    out = 1
    while n:
        if n & 1: out = gf(out, a)
        a, n = gf(a, a), n >> 1
    return out


def make_sbox():
    out = []
    for i in range(256):
        x = gf_power(i, 254) if i else 0
        y = x ^ 0x63
        for shift in range(1, 5):
            y ^= ((x << shift) | (x >> (8-shift))) & 255
        out.append(y)
    return out


SBOX = make_sbox()
INV_SBOX = [SBOX.index(i) for i in range(256)]


class AES:
    block_size = 16

    def __init__(self, key):
        if len(key) not in (16,24,32): raise ValueError('AES key must be 16, 24, or 32 bytes')
        nk = len(key)//4
        self.rounds = nk+6
        words = [list(key[i:i+4]) for i in range(0,len(key),4)]
        rcon = 1
        for i in range(nk, 4*(self.rounds+1)):
            t = words[-1][:]
            if i % nk == 0:
                t = [SBOX[x] for x in t[1:]+t[:1]]
                t[0] ^= rcon
                rcon = gf(rcon,2)
            elif nk > 6 and i % nk == 4:
                t = [SBOX[x] for x in t]
            words.append([a ^ b for a,b in zip(words[i-nk],t)])
        self.keys = [bytes(sum(words[i:i+4],[])) for i in range(0,len(words),4)]

    @staticmethod
    def shift(s, inverse=False):
        return bytes(s[4*((c+(-r if inverse else r))%4)+r] for c in range(4) for r in range(4))

    @staticmethod
    def mix(s, inverse=False):
        first = [14,11,13,9] if inverse else [2,3,1,1]
        out = []
        for c in range(4):
            col = s[4*c:4*c+4]
            for r in range(4):
                val = 0
                for j in range(4): val ^= gf(col[j],first[(j-r)%4])
                out.append(val)
        return bytes(out)

    def encrypt(self, block, trace=None):
        if len(block) != 16: raise ValueError('AES block must be 16 bytes')
        def show(label,s):
            if trace is not None: trace.append((label,s.hex()))
        if trace is not None:
            for i,k in enumerate(self.keys): show(f'round_key_{i:02}',k)
        s = xor(block,self.keys[0]); show('initial_add_round_key',s)
        for r in range(1,self.rounds+1):
            s = bytes(SBOX[x] for x in s); show(f'{r:02}_sub_bytes',s)
            s = self.shift(s); show(f'{r:02}_shift_rows',s)
            if r != self.rounds:
                s = self.mix(s); show(f'{r:02}_mix_columns',s)
            s = xor(s,self.keys[r]); show(f'{r:02}_add_round_key',s)
        return s

    def decrypt(self, block):
        if len(block) != 16: raise ValueError('AES block must be 16 bytes')
        s = xor(block,self.keys[-1])
        for r in range(self.rounds-1,-1,-1):
            s = self.shift(s,True)
            s = bytes(INV_SBOX[x] for x in s)
            s = xor(s,self.keys[r])
            if r: s = self.mix(s,True)
        return s


IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP = [IP.index(i)+1 for i in range(1,65)]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
DES_S = [
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]


def permute(x, table, width):
    out = 0
    for bit in table: out = (out << 1) | ((x >> (width-bit)) & 1)
    return out


class DES:
    block_size = 8
    def __init__(self,key):
        if len(key) != 8: raise ValueError('DES key must be 8 bytes (64 bits including parity)')
        k = permute(int.from_bytes(key,'big'),PC1,64)
        c,d = k >> 28,k & ((1 << 28)-1)
        self.keys = []
        for shift in [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]:
            c = ((c << shift)|(c >> (28-shift))) & ((1 << 28)-1)
            d = ((d << shift)|(d >> (28-shift))) & ((1 << 28)-1)
            self.keys.append(permute((c << 28)|d,PC2,56))

    def crypt(self,block,decrypt=False):
        if len(block) != 8: raise ValueError('DES block must be 8 bytes')
        x = permute(int.from_bytes(block,'big'),IP,64)
        l,r = x >> 32,x & 0xffffffff
        for key in self.keys[::-1] if decrypt else self.keys:
            t = permute(r,E,32)^key
            s = 0
            for i in range(8):
                v = (t >> (42-6*i)) & 63
                row, col = ((v >> 4) & 2)|(v & 1), (v >> 1) & 15
                s = (s << 4)|DES_S[i][row*16+col]
            l,r = r,l ^ permute(s,P,32)
        return permute((r << 32)|l,FP,64).to_bytes(8,'big')

    def encrypt(self,b): return self.crypt(b)
    def decrypt(self,b): return self.crypt(b,True)


class TripleDES:
    block_size = 8
    def __init__(self,key,backend='pure'):
        if len(key) not in (16,24): raise ValueError('3DES key must be 16 or 24 bytes')
        if len(key)==16: key += key[:8]
        if backend=='lib':
            from Crypto.Cipher import DES as LibDES
            self.parts = [LibDES.new(key[i:i+8],LibDES.MODE_ECB) for i in (0,8,16)]
        else:
            self.parts = [DES(key[i:i+8]) for i in (0,8,16)]
    def encrypt(self,b):
        a,c,d = self.parts
        return d.encrypt(c.decrypt(a.encrypt(b)))
    def decrypt(self,b):
        a,c,d = self.parts
        return a.decrypt(c.encrypt(d.decrypt(b)))


def cipher(algorithm,key,backend='pure'):
    if algorithm=='3DES': return TripleDES(key,backend)
    if algorithm not in ('AES','DES'): raise ValueError('Unknown block cipher')
    if backend=='lib':
        from Crypto.Cipher import AES as LibAES, DES as LibDES
        cls = LibAES if algorithm=='AES' else LibDES
        return cls.new(key,cls.MODE_ECB)
    return (AES if algorithm=='AES' else DES)(key)


def pad(data,bs):
    n = bs-len(data)%bs
    return data+bytes([n])*n


def unpad(data,bs):
    if not data or not 1 <= data[-1] <= bs or data[-data[-1]:] != bytes([data[-1]])*data[-1]:
        raise ValueError('Invalid PKCS#7 padding')
    return data[:-data[-1]]


def crypt(data,key,algorithm='AES',mode='CBC',decrypt=False,iv=None,nonce=b'',counter=0,backend='pure',padding=True):
    obj = cipher(algorithm,key,backend)
    bs = obj.block_size
    mode = mode.upper()
    if mode not in ('ECB','CBC','CFB','OFB','CTR'): raise ValueError('Unsupported mode')
    if mode in ('CBC','CFB','OFB') and (iv is None or len(iv)!=bs): raise ValueError(f'IV must be {bs} bytes')
    if mode=='CTR':
        if len(nonce)>=bs or counter<0: raise ValueError('CTR needs a nonce shorter than the block and a nonnegative counter')
        if counter+(len(data)+bs-1)//bs > 1 << (8*(bs-len(nonce))): raise ValueError('Counter would wrap')
    if mode in ('ECB','CBC'):
        if padding and not decrypt: data = pad(data,bs)
        if len(data)%bs: raise ValueError('Input must contain complete blocks')
    out, previous = bytearray(),iv
    for i in range(0,len(data),bs):
        block = data[i:i+bs]
        if mode=='ECB': result = obj.decrypt(block) if decrypt else obj.encrypt(block)
        elif mode=='CBC':
            result = xor(obj.decrypt(block),previous) if decrypt else obj.encrypt(xor(block,previous))
            previous = block if decrypt else result
        elif mode=='CFB':
            result = xor(block,obj.encrypt(previous))
            previous = block if decrypt else result
        elif mode=='OFB':
            previous = obj.encrypt(previous)
            result = xor(block,previous)
        else:
            result = xor(block,obj.encrypt(nonce+counter.to_bytes(bs-len(nonce),'big')))
            counter += 1
        out.extend(result)
    return unpad(bytes(out),bs) if decrypt and padding and mode in ('ECB','CBC') else bytes(out)


def main():
    """Run one simple encrypt/decrypt round-trip from a menu."""

    while True:
        print("\n=== Block ciphers ===")
        print("1. AES-CBC")
        print("2. DES-CBC")
        print("3. 3DES-ECB")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        settings = {
            "1": ("AES", b"K" * 16, "CBC", b"I" * 16),
            "2": ("DES", b"A1B2C3D4", "CBC", b"12345678"),
            "3": ("3DES", b"12345678" * 3, "ECB", None),
        }
        selected = settings.get(choice)
        if selected is None:
            print("Invalid choice.")
            continue
        algorithm, key, mode, iv = selected
        message = input("Message (Enter uses a sample): ") or "Information Security"
        try:
            encrypted = crypt(message.encode(), key, algorithm, mode, iv=iv)
            recovered = crypt(encrypted, key, algorithm, mode, decrypt=True, iv=iv)
            print("Ciphertext:", encrypted.hex())
            print("Recovered:", recovered.decode())
        except ValueError as exc:
            print(f"Could not run example: {exc}")


if __name__=='__main__': main()
