"""Lab 3/4 primitives: RSA/OAEP/PSS, ElGamal, Rabin, DH and P-256.
Pure means no third-party imports; hashlib, hmac and secrets are stdlib.
"""
import argparse
import hashlib
import hmac
import secrets
from math import gcd, isqrt
from symmetric import xor, crypt

# RFC 3526 group 14, 2048-bit MODP safe prime.
DH_P = int('''FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD
3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44
C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B
1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163
FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966
D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'''.replace('\n',''),16)
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P-3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def prime(n,rounds=32):
    if n<2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n%p==0: return n==p
    d,s=n-1,0
    while d%2==0: d,s=d//2,s+1
    for _ in range(rounds):
        a=secrets.randbelow(n-3)+2
        x=pow(a,d,n)
        if x in (1,n-1): continue
        for _ in range(s-1):
            x=pow(x,2,n)
            if x==n-1: break
        else: return False
    return True


def generate_prime(bits,blum=False,backend='pure'):
    if bits<3: raise ValueError('Prime needs at least 3 bits')
    if backend=='lib':
        from Crypto.Util.number import getPrime
        while True:
            p=getPrime(bits)
            if not blum or p%4==3: return p
    while True:
        p=secrets.randbits(bits)|(1 << (bits-1))|1
        if blum: p |= 3
        if prime(p): return p


def rsa_key(bits=2048,backend='pure'):
    if bits<16: raise ValueError('RSA modulus must have at least 16 bits for demo generation')
    if backend=='lib':
        from Crypto.PublicKey import RSA
        key=RSA.generate(bits)
        return {k:int(getattr(key,k)) for k in ('n','e','d','p','q')}
    e=65537
    while True:
        p,q=generate_prime(bits//2),generate_prime(bits-bits//2)
        phi=(p-1)*(q-1)
        if p!=q and (p*q).bit_length()==bits and gcd(e,phi)==1:
            return dict(n=p*q,e=e,d=pow(e,-1,phi),p=p,q=q)


def modexp(a,b,n,backend='pure'):
    if backend=='lib':
        from Crypto.Math.Numbers import Integer
        return int(pow(Integer(a),Integer(b),Integer(n)))
    return pow(a,b,n)


def raw_rsa(data,n,exponent,backend='pure'):
    if n<=255: raise ValueError('Bytewise RSA requires n > 255')
    return [modexp(x,exponent,n,backend) for x in data]


def mgf(seed,length):
    return b''.join(hashlib.sha256(seed+i.to_bytes(4,'big')).digest() for i in range((length+31)//32))[:length]


def oaep_encrypt(data,key,backend='pure'):
    if backend=='lib':
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        return PKCS1_OAEP.new(RSA.construct((key['n'],key['e'])),hashAlgo=SHA256).encrypt(data)
    k=(key['n'].bit_length()+7)//8
    if len(data)>k-66: raise ValueError('Message too long for RSA-OAEP-SHA256; use hybrid encryption')
    db=hashlib.sha256(b'').digest()+b'\0'*(k-len(data)-66)+b'\1'+data
    seed=secrets.token_bytes(32)
    masked_db=xor(db,mgf(seed,k-33))
    em=b'\0'+xor(seed,mgf(masked_db,32))+masked_db
    return pow(int.from_bytes(em,'big'),key['e'],key['n']).to_bytes(k,'big')


def oaep_decrypt(data,key,backend='pure'):
    if backend=='lib':
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        return PKCS1_OAEP.new(RSA.construct(tuple(key[x] for x in ('n','e','d','p','q'))),hashAlgo=SHA256).decrypt(data)
    k=(key['n'].bit_length()+7)//8
    if len(data)!=k or int.from_bytes(data,'big')>=key['n']: raise ValueError('Invalid OAEP ciphertext')
    em=pow(int.from_bytes(data,'big'),key['d'],key['n']).to_bytes(k,'big')
    seed=xor(em[1:33],mgf(em[33:],32))
    db=xor(em[33:],mgf(seed,k-33))
    rest=db[32:]
    i=rest.find(b'\1')
    if em[0] or not hmac.compare_digest(db[:32],hashlib.sha256(b'').digest()) or i<0 or any(rest[:i]):
        raise ValueError('Invalid OAEP ciphertext')
    return rest[i+1:]


def sign(data,key,backend='pure'):
    if backend=='lib':
        from Crypto.Signature import pss
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        return pss.new(RSA.construct(tuple(key[x] for x in ('n','e','d','p','q')))).sign(SHA256.new(data))
    bits=key['n'].bit_length()-1; size=(bits+7)//8
    if size<66: raise ValueError('RSA modulus too small for PSS-SHA256')
    salt=secrets.token_bytes(32)
    digest=hashlib.sha256(b'\0'*8+hashlib.sha256(data).digest()+salt).digest()
    db=b'\0'*(size-66)+b'\1'+salt
    masked=bytearray(xor(db,mgf(digest,size-33)))
    masked[0] &= 255 >> (8*size-bits)
    em=bytes(masked)+digest+b'\xbc'
    return pow(int.from_bytes(em,'big'),key['d'],key['n']).to_bytes((key['n'].bit_length()+7)//8,'big')


def verify(data,signature,key,backend='pure'):
    if backend=='lib':
        from Crypto.Signature import pss
        from Crypto.PublicKey import RSA
        from Crypto.Hash import SHA256
        try: pss.new(RSA.construct((key['n'],key['e']))).verify(SHA256.new(data),signature); return True
        except (ValueError,TypeError): return False
    bits=key['n'].bit_length()-1; size=(bits+7)//8
    if size<66 or len(signature)!=(key['n'].bit_length()+7)//8 or int.from_bytes(signature,'big')>=key['n']: return False
    v=pow(int.from_bytes(signature,'big'),key['e'],key['n'])
    if v.bit_length()>size*8: return False
    em=v.to_bytes(size,'big'); digest=em[-33:-1]; masked=em[:-33]
    if em[-1]!=188 or masked[0] >> (8-(8*size-bits)): return False
    db=bytearray(xor(masked,mgf(digest,size-33))); db[0] &= 255 >> (8*size-bits)
    if any(db[:size-66]) or db[size-66]!=1: return False
    return hmac.compare_digest(digest,hashlib.sha256(b'\0'*8+hashlib.sha256(data).digest()+bytes(db[-32:])).digest())


def elgamal_encrypt(message,p,g,h,backend='pure'):
    if not 1<g<p or not 1<h<p or any(not 0<=m<p for m in message): raise ValueError('Invalid ElGamal parameters or message >= p')
    out=[]
    for m in message:
        k=secrets.randbelow(p-3)+2
        out.append((modexp(g,k,p,backend),m*modexp(h,k,p,backend)%p))
    return out


def elgamal_decrypt(pairs,p,x,backend='pure'):
    if not 1<=x<p-1: raise ValueError('Invalid ElGamal private exponent')
    if any(not 0<c1<p or not 0<=c2<p for c1,c2 in pairs): raise ValueError('Invalid ElGamal ciphertext')
    return [c2*pow(modexp(c1,x,p,backend),-1,p)%p for c1,c2 in pairs]


def validate_point(point):
    if point is None or len(point)!=2: raise ValueError('Point at infinity is not an external public key')
    x,y=point
    if not 0<=x<P or not 0<=y<P or (y*y-x*x*x-A*x-B)%P: raise ValueError('Point not on P-256')
    return tuple(point)


def add(p,q):
    if p is None: return q
    if q is None: return p
    x,y=p; u,v=q
    if x==u and (y+v)%P==0: return None
    slope=((3*x*x+A)*pow(2*y,-1,P) if p==q else (v-y)*pow(u-x,-1,P))%P
    z=(slope*slope-x-u)%P
    return z,(slope*(x-z)-y)%P


def multiply(k,point=G,backend='pure'):
    if point is None or k%N==0: return None
    point=validate_point(point); k %= N
    if backend=='lib':
        from Crypto.PublicKey.ECC import EccPoint
        result=EccPoint(*point,curve='P-256')*k
        return int(result.x),int(result.y)
    out=None
    while k:
        if k&1: out=add(out,point)
        point=add(point,point); k>>=1
    return out


def ec_add(p,q,backend='pure'):
    if backend=='pure' or p is None or q is None: return add(p,q)
    from Crypto.PublicKey.ECC import EccPoint
    out=EccPoint(*p,curve='P-256')+EccPoint(*q,curve='P-256')
    return None if out.is_point_at_infinity() else (int(out.x),int(out.y))


def ecdh(d,q,backend='pure'):
    validate_point(q)
    if not 1<=d<N: raise ValueError('Invalid private scalar')
    if backend=='lib':
        from cryptography.hazmat.primitives.asymmetric import ec
        private=ec.derive_private_key(d,ec.SECP256R1())
        public=ec.EllipticCurvePublicNumbers(*q,ec.SECP256R1()).public_key()
        return private.exchange(ec.ECDH(),public)
    return multiply(d,q)[0].to_bytes(32,'big')


def hkdf(secret,salt=b'',info=b'ISLAB-v1',length=64):
    if not 0<=length<=255*32: raise ValueError('Invalid HKDF length')
    prk=hmac.new(salt,secret,hashlib.sha256).digest(); out=b''; last=b''
    for i in range(1,(length+31)//32+1):
        last=hmac.new(prk,last+info+bytes([i]),hashlib.sha256).digest(); out+=last
    return out[:length]


def seal(data,secret,backend='pure',aad=b''):
    salt,nonce=secrets.token_bytes(16),secrets.token_bytes(8)
    keys=hkdf(secret,salt)
    ciphertext=crypt(data,keys[:32],mode='CTR',nonce=nonce,backend=backend)
    body=salt+nonce+ciphertext
    return body+hmac.new(keys[32:],len(aad).to_bytes(8,'big')+aad+body,hashlib.sha256).digest()


def unseal(data,secret,backend='pure',aad=b''):
    if len(data)<56: raise ValueError('Truncated envelope')
    keys=hkdf(secret,data[:16])
    expected=hmac.new(keys[32:],len(aad).to_bytes(8,'big')+aad+data[:-32],hashlib.sha256).digest()
    if not hmac.compare_digest(expected,data[-32:]): raise ValueError('Authentication failed')
    return crypt(data[24:-32],keys[:32],mode='CTR',nonce=data[16:24],backend=backend)


def rabin_key(bits=1024,backend='pure'):
    if bits<16: raise ValueError('Rabin key must be at least 16 bits')
    while True:
        p,q=generate_prime(bits//2,True,backend),generate_prime(bits-bits//2,True,backend)
        if p!=q and (p*q).bit_length()==bits: return dict(n=p*q,p=p,q=q)


def rabin_roots(c,p,q):
    if p==q or p%4!=3 or q%4!=3 or not 0<=c<p*q: raise ValueError('Rabin requires distinct Blum primes and 0 <= c < n')
    a,b=pow(c,(p+1)//4,p),pow(c,(q+1)//4,q)
    roots={(u*q*pow(q,-1,p)+v*p*pow(p,-1,q))%(p*q) for u in (a,-a) for v in (b,-b)}
    if any(r*r%(p*q)!=c for r in roots): raise ValueError('Not a quadratic residue')
    return sorted(roots)


def dh_shared(private,public,p=DH_P,g=2,backend='pure'):
    if not 2<=private<p-1 or not 2<=public<=p-2: raise ValueError('Invalid DH exponent/public value')
    if p==DH_P and pow(public,(p-1)//2,p)!=1: raise ValueError('DH public value outside subgroup')
    return modexp(public,private,p,backend)


def factor(n,method='trial',limit=1000000):
    if n<4: raise ValueError('n must be composite')
    if n%2==0: return 2,n//2
    if method=='trial':
        for p in range(3,min(isqrt(n),limit)+1,2):
            if n%p==0: return p,n//p
    elif method=='fermat':
        a=isqrt(n)
        if a*a<n: a+=1
        for _ in range(limit):
            b=isqrt(a*a-n)
            if b*b==a*a-n and a!=b and a-b>1: return a-b,a+b
            a+=1
    elif method=='rho':
        for seed in range(2,7):
            x=y=seed
            for _ in range(limit//5):
                x=(x*x+1)%n; y=(y*y+1)%n; y=(y*y+1)%n
                d=gcd(abs(x-y),n)
                if 1<d<n: return d,n//d
                if d==n: break
    else: raise ValueError('Unknown factor method')
    raise ValueError('No factor within limit; increase --limit or change method')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('algorithm',choices=['rsa','elgamal','dh','ecc','rabin','factor'])
    p.add_argument('--message',default='Confidential Data')
    p.add_argument('--backend',choices=['pure','lib'],default='pure')
    p.add_argument('--bits',type=int,default=2048)
    p.add_argument('--n',type=int,default=323); p.add_argument('--e',type=int,default=5); p.add_argument('--d',type=int,default=173)
    p.add_argument('--p',type=int,default=7919); p.add_argument('--q',type=int,default=499)
    p.add_argument('--g',type=int,default=2); p.add_argument('--x',type=int,default=2999); p.add_argument('--h',type=int)
    p.add_argument('--raw',action='store_true')
    p.add_argument('--method',choices=['trial','fermat','rho'],default='trial'); p.add_argument('--limit',type=int,default=1000000)
    a=p.parse_args()
    try:
        if a.algorithm=='rsa':
            if a.raw:
                c=raw_rsa(a.message.encode(),a.n,a.e,a.backend); print('Ciphertext integers:',c)
                print('Recovered:',bytes(raw_rsa(c,a.n,a.d,a.backend)).decode())
            else:
                key=rsa_key(a.bits,a.backend); c=oaep_encrypt(a.message.encode(),key,a.backend)
                print('Ciphertext:',c.hex()); print('Recovered:',oaep_decrypt(c,key,a.backend).decode())
        elif a.algorithm=='elgamal':
            if not prime(a.p): raise ValueError('p must be prime')
            h=pow(a.g,a.x,a.p) if a.h is None else a.h
            if h!=pow(a.g,a.x,a.p): raise ValueError(f'Inconsistent key: h should be {pow(a.g,a.x,a.p)} for this x')
            c=elgamal_encrypt(a.message.encode(),a.p,a.g,h,a.backend); print('Ciphertext:',c)
            print('Recovered:',bytes(elgamal_decrypt(c,a.p,a.x,a.backend)).decode())
        elif a.algorithm=='ecc':
            x,y=secrets.randbelow(N-1)+1,secrets.randbelow(N-1)+1
            q=multiply(y,backend=a.backend)
            secret=ecdh(x,q,a.backend); assert secret==ecdh(y,multiply(x,backend=a.backend),a.backend)
            c=seal(a.message.encode(),secret,a.backend); print('Envelope:',c.hex()); print('Recovered:',unseal(c,secret,a.backend).decode())
        elif a.algorithm=='dh':
            from time import perf_counter
            t=perf_counter(); x,y=secrets.randbelow(DH_P-4)+2,secrets.randbelow(DH_P-4)+2
            X,Y=modexp(2,x,DH_P,a.backend),modexp(2,y,DH_P,a.backend); generated=perf_counter()-t
            t=perf_counter(); s=dh_shared(x,Y,backend=a.backend); other=dh_shared(y,X,backend=a.backend); elapsed=perf_counter()-t
            assert s==other
            print('Shared secrets match:',True,'keygen seconds:',generated,'exchange seconds:',elapsed)
            print('Derived key fingerprint:',hashlib.sha256(hkdf(s.to_bytes(256,'big'))).hexdigest())
        elif a.algorithm=='rabin':
            key=rabin_key(a.bits,a.backend); m=int.from_bytes(a.message.encode(),'big')
            if m>=key['n']: raise ValueError('Message too large; use a larger key or hybrid')
            c=pow(m,2,key['n']); roots=rabin_roots(c,key['p'],key['q'])
            print('Ciphertext:',c,'\nFour candidate integers:',roots,'\nOriginal is among roots:',m in roots)
        else:
            if a.backend=='lib':
                from sympy import factorint
                factors=factorint(a.n,limit=a.limit)
                if len(factors)!=2 or any(v!=1 or not prime(int(k)) for k,v in factors.items()): raise ValueError('Need two distinct prime factors')
                u,v=map(int,factors)
            else: u,v=factor(a.n,a.method,a.limit)
            if not prime(u) or not prime(v) or u==v: raise ValueError('Recovered factors are not two distinct primes')
            print('p, q:',u,v,'private d:',pow(a.e,-1,(u-1)*(v-1)))
    except (ValueError,OverflowError,UnicodeDecodeError) as e: p.error(str(e))


if __name__=='__main__': main()
