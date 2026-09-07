"""Likely evaluation modifications and attack demonstrations; --list names all cases.
These controlled examples use locally generated data. Edit parameters or import functions.
"""
import argparse
import hashlib
import hmac
import secrets
from math import gcd,isqrt
import classical as c
import symmetric as s
import public_key as p
import hybrid


def recover_affine(plain,cipher,backend='pure'):
    return [(a,b) for a,b,_ in c.candidates('',plain,cipher,backend=backend)]


def recover_hill(plain,cipher,n=2,backend='pure'):
    plain,cipher=c.clean(plain),c.clean(cipher)
    if len(plain)!=len(cipher) or len(plain)<n*n: raise ValueError('Need matching plaintext/ciphertext with at least n*n symbols')
    from itertools import combinations
    # ponytail: try block combinations for small lab inputs; large corpora need linear solving modulo 2 and 13.
    blocks=len(plain)//n
    for indices in combinations(range(blocks),n):
        pm=[[ord(plain[k*n+r])-65 for k in indices] for r in range(n)]
        cm=[[ord(cipher[k*n+r])-65 for k in indices] for r in range(n)]
        try: inv=c.matrix_inverse(pm,backend)
        except ValueError: continue
        key=[[sum(cm[r][k]*inv[k][col] for k in range(n))%26 for col in range(n)] for r in range(n)]
        if c.hill(plain,key,backend=backend)==cipher: return key
    raise ValueError('No invertible known-plaintext block matrix or inconsistent pairs')


def frequency_caesar(text):
    expected=[8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,.153,.772,4.025,2.406,6.749,7.507,1.929,.095,5.987,6.327,9.056,2.758,.978,2.360,.150,1.974,.074]
    text=c.clean(text)
    if not text: raise ValueError('Need letters for frequency scoring')
    rows=[]
    for key in range(26):
        plain=c.affine(text,1,key,True)
        score=sum((plain.count(letter)-len(plain)*freq/100)**2/(len(plain)*freq/100) for letter,freq in zip(c.ABC,expected))
        rows.append((score,key,plain))
    return sorted(rows)


def vigenere_guess(cipher,max_length=12):
    text=c.clean(cipher); answers=[]
    for length in range(1,min(max_length,len(text))+1):
        key=''.join(c.ABC[frequency_caesar(text[i::length])[0][1]] for i in range(length))
        groups=[text[i::length] for i in range(length)]
        ic=sum(sum(g.count(x)*(g.count(x)-1) for x in c.ABC)/(len(g)*(len(g)-1)) if len(g)>1 else 0 for g in groups)/length
        answers.append((length,ic,key,c.vigenere(text,key,True)))
    return answers


def integer_root(value,e):
    if value<0 or e<1: raise ValueError('Root needs nonnegative value and positive exponent')
    low,high=0,1 << ((value.bit_length()+e-1)//e+1)
    while low+1<high:
        mid=(low+high)//2
        if mid**e<=value: low=mid
        else: high=mid
    return low,low**e==value


def egcd(a,b):
    if not b: return a,1,0
    g,x,y=egcd(b,a%b); return g,y,x-(a//b)*y


def common_modulus(n,e1,e2,c1,c2):
    g,a,b=egcd(e1,e2)
    if g!=1: raise ValueError('Public exponents must be coprime')
    return pow(c1,a,n)*pow(c2,b,n)%n


def partial_prime(n,known_high,unknown_bits):
    if not 0<=unknown_bits<=24: raise ValueError('Bounded demo supports 0..24 missing low bits')
    for low in range(1 << unknown_bits):
        guess=(known_high << unknown_bits)|low
        if guess>1 and n%guess==0: return guess,n//guess
    raise ValueError('No factor matches those known bits')


def access(model,clearance=2,classification=1,action='read',role='doctor',owner=False,hour=12):
    if action not in ('read','write'): raise ValueError('Action must be read or write')
    if model=='rbac': return action in {'doctor':{'read','write'},'nurse':{'read'},'guest':set()}.get(role,set())
    if model=='abac': return role in ('doctor','nurse') and clearance>=classification and 8<=hour<18 and (action=='read' or role=='doctor')
    if model=='blp': return clearance>=classification if action=='read' else clearance<=classification
    if model=='dac': return owner
    if model=='time': return 8<=hour<18
    raise ValueError('Unknown policy')


CASES={
'affine-known':'Recover affine keys from arbitrary matching text',
'caesar-frequency':'Rank all Caesar keys by English chi-squared score',
'vigenere-analysis':'Try key lengths, IC and frequency-derived keywords',
'hill-known':'Recover a Hill matrix from independent known blocks',
'hill-3x3':'Larger Hill key and padding',
'playfair-edge':'Repeated X, repeated letters, odd length and J/I',
'rail':'Rail-fence encryption/decryption',
'columnar':'Columnar transposition with duplicate keyword letters',
'double-transposition':'Two successive columnar permutations',
'pipeline':'Affine then Vigenere then transposition; reverse order to decrypt',
'aes-avalanche':'Flip one input bit and count changed ciphertext bits',
'ecb-pattern':'Repeated plaintext blocks produce repeated ECB blocks',
'cbc-bitflip':'Changing the IV predictably changes first plaintext block',
'ctr-reuse':'Recover second plaintext when CTR keystream is reused',
'padding':'Valid and invalid PKCS#7; aligned input gets full padding block',
'authenticated-tamper':'Authenticated hybrid rejects modified ciphertext',
'gcm':'Library AES-GCM encryption and tag verification',
'rsa-crt':'RSA CRT decryption equals modular exponentiation',
'rsa-common-modulus':'Recover raw RSA plaintext from two coprime exponents',
'rsa-shared-prime':'GCD finds a prime reused across RSA keys',
'rsa-small-message':'Integer-root recovery when raw RSA m^e < n',
'rsa-partial-prime':'Brute force a bounded number of missing prime bits',
'rsa-fermat':'Factor close primes and recover the private key',
'elgamal-reuse':'Known plaintext breaks a reused multiplicative mask',
'ec-elgamal-point':'Encrypt/decrypt a P-256 point: C1=kG,C2=M+kQ',
'dh-mitm':'Unauthenticated DH permits two attacker-controlled secrets',
'rabin-roots':'Show all four roots and the ambiguity',
'signature':'RSA-PSS verifies original and rejects changed document',
'hash-hmac':'SHA-256 digest versus keyed HMAC authentication',
'password-kdf':'Salted PBKDF2 derivation and verification',
'access-policies':'RBAC, ABAC, Bell-LaPadula, DAC and time checks',
'nonce-randomness':'Same message/key encrypts differently with fresh envelopes'
}


def run(name,backend='pure',text=None,key=None):
    print('\n===',name,CASES[name],'===')
    if name=='affine-known': print('Candidates:',recover_affine(text or 'ab',key or 'GL',backend))
    elif name=='caesar-frequency':
        for row in frequency_caesar(text or c.affine('THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RETURNS HOME',1,13))[:5]: print(row)
    elif name=='vigenere-analysis':
        for row in vigenere_guess(text or c.vigenere('THE HOUSE IS BEING SOLD TONIGHT AND WE WILL RETURN TO THE HOUSE TOMORROW','KEY')): print(row)
        print('Statistical guesses, not guaranteed recovery; short messages may rank incorrectly.')
    elif name=='hill-known':
        plain=text or 'BAAB'; cipher=key or 'DCDH'
        print('Recovered matrix:',recover_hill(plain,cipher,backend=backend))
    elif name=='hill-3x3':
        matrix=[[6,24,1],[13,16,10],[20,17,15]]; message=text or 'ACT'
        ciphertext=c.hill(message,matrix,backend=backend); print(ciphertext,c.hill(ciphertext,matrix,True,backend))
    elif name=='playfair-edge':
        message=text or 'BALLOON XX JAZZ'; ciphertext=c.playfair(message,key or 'GUIDANCE',backend=backend)
        print(ciphertext,c.playfair(ciphertext,key or 'GUIDANCE',True,backend))
    elif name in ('rail','columnar','double-transposition'):
        message=text or 'WE ARE DISCOVERED. FLEE AT ONCE!'
        if name=='rail': encrypted=c.rail(message,int(key or 3)); decrypted=c.rail(encrypted,int(key or 3),True)
        elif name=='columnar': encrypted=c.columnar(message,key or 'BALLOON'); decrypted=c.columnar(encrypted,key or 'BALLOON',True)
        else: encrypted=c.columnar(c.columnar(message,key or 'ZEBRA'),'CARGO'); decrypted=c.columnar(c.columnar(encrypted,'CARGO',True),key or 'ZEBRA',True)
        assert decrypted==message; print(encrypted,'\nRecovered:',decrypted)
    elif name=='pipeline':
        message=c.clean(text or 'Information security'); encrypted=c.columnar(c.vigenere(c.affine(message,15,20),'KEY'),'ZEBRA')
        decrypted=c.affine(c.vigenere(c.columnar(encrypted,'ZEBRA',True),'KEY',True),15,20,True)
        assert decrypted==message; print(encrypted,decrypted)
    elif name=='aes-avalanche':
        block=bytes(16); changed=b'\x01'+bytes(15); cipher=s.cipher('AES',bytes(range(16)),backend)
        print('Changed bits out of 128:',sum(x.bit_count() for x in s.xor(cipher.encrypt(block),cipher.encrypt(changed))))
    elif name=='ecb-pattern':
        block=b'YELLOW SUBMARINE'; encrypted=s.crypt(block*3,bytes(16),mode='ECB',backend=backend,padding=False)
        chunks=[encrypted[i:i+16].hex() for i in range(0,len(encrypted),16)]; assert len(set(chunks))==1; print(chunks)
    elif name=='cbc-bitflip':
        message=b'admin=0;amount=10'; keybytes=secrets.token_bytes(16); iv=secrets.token_bytes(16)
        ciphertext=s.crypt(message,keybytes,mode='CBC',iv=iv,backend=backend)
        altered=bytearray(iv); altered[6]^=ord('0')^ord('1')
        plain=s.crypt(ciphertext,keybytes,mode='CBC',iv=bytes(altered),decrypt=True,backend=backend)
        assert plain==b'admin=1;amount=10'; print(plain)
    elif name=='ctr-reuse':
        m1=b'Known message 123'; m2=b'Hidden secret 456'; keybytes=secrets.token_bytes(16); nonce=bytes(8)
        c1=s.crypt(m1,keybytes,mode='CTR',nonce=nonce,backend=backend); c2=s.crypt(m2,keybytes,mode='CTR',nonce=nonce,backend=backend)
        recovered=s.xor(s.xor(c1,c2),m1); assert recovered==m2; print('Recovered:',recovered)
    elif name=='padding':
        for message in [b'',b'A',b'A'*16]:
            padded=s.pad(message,16); assert s.unpad(padded,16)==message; print(len(message),'->',len(padded),padded.hex())
        try: s.unpad(b'A'*15+b'\0',16)
        except ValueError: print('Invalid padding rejected')
        else: raise AssertionError('Bad padding accepted')
    elif name in ('authenticated-tamper','nonce-randomness'):
        recipient=hybrid.keygen('ecc',backend); message=(text or 'Secure message').encode()
        encrypted=hybrid.encrypt(message,hybrid.public(recipient),backend)
        if name=='nonce-randomness':
            second=hybrid.encrypt(message,hybrid.public(recipient),backend); assert encrypted!=second
            print('Two randomized envelopes differ and both decrypt:',hybrid.decrypt(encrypted,recipient,backend)==hybrid.decrypt(second,recipient,backend)==message)
        else:
            tampered=encrypted[:-1]+bytes([encrypted[-1]^1])
            try: hybrid.decrypt(tampered,recipient,backend)
            except ValueError: print('Tampering rejected before plaintext release')
            else: raise AssertionError('Tampered ciphertext accepted')
    elif name=='gcm':
        if backend=='pure':
            print('GCM is a library-only extension; pure authenticated counterpart uses AES-CTR + HMAC (different construction).'); return
        from Crypto.Cipher import AES
        keybytes=secrets.token_bytes(32); cipher=AES.new(keybytes,AES.MODE_GCM,nonce=secrets.token_bytes(12)); cipher.update(b'header')
        ct,tag=cipher.encrypt_and_digest((text or 'Authenticated message').encode())
        other=AES.new(keybytes,AES.MODE_GCM,nonce=cipher.nonce); other.update(b'header')
        print('Recovered:',other.decrypt_and_verify(ct,tag))
    elif name=='rsa-crt':
        u,v,e=61,53,17; n=u*v; d=pow(e,-1,(u-1)*(v-1)); cipher=pow(65,e,n)
        a,b=pow(cipher,d%(u-1),u),pow(cipher,d%(v-1),v)
        recovered=b+v*((a-b)*pow(v,-1,u)%u); assert recovered==pow(cipher,d,n)==65; print(recovered)
    elif name=='rsa-common-modulus':
        n=61*53; message=42; recovered=common_modulus(n,7,11,pow(message,7,n),pow(message,11,n)); assert recovered==message; print(recovered)
    elif name=='rsa-shared-prime':
        n1,n2=1009*1013,1009*1019; shared=gcd(n1,n2); assert shared==1009; print('shared p:',shared,'q1:',n1//shared,'q2:',n2//shared)
    elif name=='rsa-small-message':
        message=42; root,exact=integer_root(message**3,3); assert exact and root==message; print(root,exact)
    elif name=='rsa-partial-prime':
        n=1009*1013; print(partial_prime(n,1009 >> 5,5))
    elif name=='rsa-fermat': print(p.factor(1000003*1000033,'fermat'))
    elif name=='elgamal-reuse':
        modulus,g,x,k=7919,2,2999,101; mask=pow(pow(g,x,modulus),k,modulus)
        known,hidden=65,90; c2a,c2b=known*mask%modulus,hidden*mask%modulus
        recovered=c2b*pow(c2a,-1,modulus)*known%modulus; assert recovered==hidden; print(recovered)
    elif name=='ec-elgamal-point':
        d,k=12345,98765; message=p.multiply(42,backend=backend); public=p.multiply(d,backend=backend)
        c1=p.multiply(k,backend=backend); c2=p.ec_add(message,p.multiply(k,public,backend),backend)
        shared=p.multiply(d,c1,backend); recovered=p.ec_add(c2,(shared[0],-shared[1]%p.P),backend)
        assert recovered==message; print('C1:',c1,'\nC2:',c2,'\nRecovered point:',recovered)
    elif name=='dh-mitm':
        modulus,g=23,5; a,b,m1,m2=6,15,7,9
        A,B=pow(g,a,modulus),pow(g,b,modulus)
        alice=pow(pow(g,m1,modulus),a,modulus); eve_a=pow(A,m1,modulus)
        bob=pow(pow(g,m2,modulus),b,modulus); eve_b=pow(B,m2,modulus)
        assert alice==eve_a and bob==eve_b; print('Alice/Eve secret:',alice,'Bob/Eve secret:',bob,'Identity authentication is missing.')
    elif name=='rabin-roots':
        roots=p.rabin_roots(pow(42,2,499*547),499,547); assert 42 in roots; print(roots)
    elif name=='signature':
        keypair=p.rsa_key(2048,backend); message=(text or 'Approved document').encode(); sig=p.sign(message,keypair,backend)
        assert p.verify(message,sig,keypair,backend) and not p.verify(message+b'!',sig,keypair,backend)
        print('Original accepted; modified document rejected.')
    elif name=='hash-hmac':
        message=(text or 'amount=100').encode(); secret=(key or 'exam-demo-key').encode()
        print('SHA256:',hashlib.sha256(message).hexdigest(),'HMAC-SHA256:',hmac.new(secret,message,hashlib.sha256).hexdigest())
        print('Anyone can recompute an unkeyed hash; only a key holder can create a valid HMAC.')
    elif name=='password-kdf':
        salt=secrets.token_bytes(16); password=(text or 'exam-password').encode(); iterations=600000
        derived=hashlib.pbkdf2_hmac('sha256',password,salt,iterations)
        assert hmac.compare_digest(derived,hashlib.pbkdf2_hmac('sha256',password,salt,iterations))
        print('salt:',salt.hex(),'iterations:',iterations,'derived:',derived.hex())
    elif name=='access-policies':
        for model in ['rbac','abac','blp','dac','time']:
            print(model,{action:access(model,action=action) for action in ['read','write']})
        assert access('blp',2,1,'read') and not access('blp',2,1,'write')
        assert not access('rbac',role='guest')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case',nargs='?',choices=CASES); parser.add_argument('--list',action='store_true'); parser.add_argument('--all',action='store_true')
    parser.add_argument('--backend',choices=['pure','lib'],default='pure'); parser.add_argument('--text'); parser.add_argument('--key')
    args=parser.parse_args()
    if args.list or not args.case and not args.all:
        for k,v in CASES.items(): print(k,v)
    else:
        for case in CASES if args.all else [args.case]: run(case,args.backend,args.text,args.key)


if __name__=='__main__': main()
