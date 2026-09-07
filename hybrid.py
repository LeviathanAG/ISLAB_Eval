"""Authenticated hybrid file encryption with RSA, ECC, EC-ElGamal, ElGamal or Rabin.
JSON header + salt + nonce + ciphertext + HMAC; header is authenticated.
"""
import argparse
import json
import secrets
import struct
from pathlib import Path
from public_key import (DH_P, N, multiply, validate_point, ecdh, ec_add, rsa_key,
                        rabin_key, rabin_roots, oaep_encrypt, oaep_decrypt, seal,
                        unseal, modexp, generate_prime, prime)


def encode(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def keygen(algorithm,backend='pure',bits=2048):
    if algorithm=='rsa': key=rsa_key(bits,backend)
    elif algorithm in ('ecc','ec-elgamal'):
        d=secrets.randbelow(N-1)+1; key=dict(d=d,Q=multiply(d,backend=backend))
    elif algorithm=='elgamal':
        # Fixed audited group for default; generate safe-prime group for alternate sizes.
        if bits<512: raise ValueError('Hybrid ElGamal needs at least 512 bits')
        if bits==2048: p=DH_P
        else:
            while True:
                q=generate_prime(bits-1,backend=backend); p=2*q+1
                if prime(p): break
        g=4; x=secrets.randbelow((p-1)//2-2)+2
        key=dict(p=p,g=g,x=x,h=modexp(g,x,p,backend))
    elif algorithm=='rabin': key=rabin_key(bits,backend)
    else: raise ValueError('Unknown hybrid algorithm')
    return dict(algorithm=algorithm,**key)


def public(key):
    fields={'rsa':('n','e'),'ecc':('Q',),'ec-elgamal':('Q',),'elgamal':('p','g','h'),'rabin':('n',)}
    return {k:key[k] for k in ('algorithm',)+fields[key['algorithm']]}


def encrypt(data,key,backend='pure',context=''):
    algorithm=key['algorithm']; header=dict(version=1,algorithm=algorithm,context=context)
    secret=secrets.token_bytes(32)
    if algorithm=='rsa': header['wrapped']=oaep_encrypt(secret,key,backend).hex()
    elif algorithm=='ecc':
        d=secrets.randbelow(N-1)+1
        header['ephemeral']=multiply(d,backend=backend)
        secret=ecdh(d,key['Q'],backend)
    elif algorithm=='ec-elgamal':
        r,k=secrets.randbelow(N-1)+1,secrets.randbelow(N-1)+1
        point=multiply(r,backend=backend)
        header['c1']=multiply(k,backend=backend)
        header['c2']=ec_add(point,multiply(k,key['Q'],backend),backend)
        # Infinity would be a valid internal group result, retry to keep wire format simple.
        if header['c2'] is None: return encrypt(data,key,backend,context)
        secret=encode(point)
    elif algorithm=='elgamal':
        p=key['p']; k=secrets.randbelow((p-1)//2-2)+2
        header['c1']=modexp(key['g'],k,p,backend)
        header['c2']=int.from_bytes(secret,'big')*modexp(key['h'],k,p,backend)%p
    elif algorithm=='rabin':
        import hashlib
        tagged=b'RAB1'+secret+hashlib.sha256(secret).digest()[:16]
        m=int.from_bytes(tagged,'big')
        if m>=key['n']: raise ValueError('Rabin hybrid needs modulus larger than 416 bits')
        header['wrapped']=pow(m,2,key['n'])
    else: raise ValueError('Unknown algorithm')
    head=encode(header)
    return struct.pack('>I',len(head))+head+seal(data,secret,backend,head)


def decrypt(blob,key,backend='pure',context=None):
    if len(blob)<4: raise ValueError('Truncated hybrid header')
    size=struct.unpack('>I',blob[:4])[0]
    if size>65536 or size>len(blob)-4: raise ValueError('Invalid hybrid header size')
    head=blob[4:4+size]; h=json.loads(head)
    if h['version']!=1 or h['algorithm']!=key['algorithm']: raise ValueError('Envelope algorithm/version mismatch')
    if context is not None and h['context']!=context: raise ValueError('Envelope context mismatch')
    algorithm=key['algorithm']
    if algorithm=='rsa': secret=oaep_decrypt(bytes.fromhex(h['wrapped']),key,backend)
    elif algorithm=='ecc': secret=ecdh(key['d'],h['ephemeral'],backend)
    elif algorithm=='ec-elgamal':
        c1,c2=validate_point(h['c1']),validate_point(h['c2'])
        shared=multiply(key['d'],c1,backend)
        point=ec_add(c2,(shared[0],-shared[1]%__import__('public_key').P),backend)
        validate_point(point); secret=encode(point)
    elif algorithm=='elgamal':
        p=key['p']; c1,c2=h['c1'],h['c2']
        if not 1<c1<p-1 or not 0<=c2<p or pow(c1,(p-1)//2,p)!=1: raise ValueError('Invalid ElGamal ciphertext')
        value=c2*pow(modexp(c1,key['x'],p,backend),-1,p)%p
        if value.bit_length()>256: raise ValueError('Invalid wrapped key')
        secret=value.to_bytes(32,'big')
    elif algorithm=='rabin':
        import hashlib,hmac
        matches=[]
        for root in rabin_roots(h['wrapped'],key['p'],key['q']):
            if root.bit_length()>416: continue
            tagged=root.to_bytes(52,'big')
            if tagged[:4]==b'RAB1' and hmac.compare_digest(tagged[-16:],hashlib.sha256(tagged[4:36]).digest()[:16]): matches.append(tagged[4:36])
        if len(matches)!=1: raise ValueError('Rabin root disambiguation failed')
        secret=matches[0]
    else: raise ValueError('Unknown algorithm')
    return unseal(blob[4+size:],secret,backend,head)


def write_new(path,data,private=False):
    import os
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600 if private else 0o644)
    with os.fdopen(fd,'wb') as f: f.write(data)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['keygen','encrypt','decrypt'])
    p.add_argument('--algorithm',choices=['rsa','ecc','ec-elgamal','elgamal','rabin'],default='rsa')
    p.add_argument('--backend',choices=['pure','lib'],default='pure')
    p.add_argument('--bits',type=int,default=2048)
    p.add_argument('--key',required=True,help='Key JSON path; private keys are password encrypted')
    p.add_argument('--input'); p.add_argument('--output')
    a=p.parse_args()
    try:
        import getpass,hashlib
        if a.action=='keygen':
            key=keygen(a.algorithm,a.backend,a.bits)
            password=getpass.getpass('New private-key password: ')
            if not password: raise ValueError('Password cannot be empty')
            salt=secrets.token_bytes(16)
            master=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1)
            write_new(a.key,salt+seal(encode(key),master,a.backend),True)
            write_new(a.key+'.pub',encode(public(key)))
            print('Saved encrypted private key and',a.key+'.pub')
        else:
            if not a.input or not a.output: raise ValueError('--input and --output required')
            data=Path(a.input).read_bytes(); raw=Path(a.key).read_bytes()
            if a.action=='encrypt': key=json.loads(raw); out=encrypt(data,key,a.backend)
            else:
                password=getpass.getpass('Private-key password: ')
                master=hashlib.scrypt(password.encode(),salt=raw[:16],n=2**14,r=8,p=1)
                key=json.loads(unseal(raw[16:],master,a.backend)); out=decrypt(data,key,a.backend)
            write_new(a.output,out); print('Wrote',len(out),'bytes to',a.output)
    except (ValueError,KeyError,OSError,OverflowError) as e: p.error(str(e))


if __name__=='__main__': main()
