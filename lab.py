"""Run any manual exercise from Labs 1-6: python lab.py L1Q1 --backend pure.
Use --list for the full index, --all for all questions. Algorithms accept custom
inputs through classical.py, symmetric.py, public_key.py, hybrid.py, variants.py.
"""
import argparse
import secrets
import time
import classical as c
import symmetric as s
import public_key as p
import hybrid
import services
import benchmarks
import hashing
import digital_signatures as ds
import socket
import threading

QUESTIONS={
'L1Q1':'Additive, multiplicative and affine encryption',
'L1Q2':'Vigenere and plaintext autokey',
'L1Q3':'Playfair GUIDANCE',
'L1Q4':'Hill 2x2 cipher',
'L1Q5':'Known-plaintext shift attack',
'L1Q6':'Affine brute force with ab -> GL',
'L1A1':'Birthday-guided Caesar brute force',
'L1A2':'Chosen-plaintext permutation inference',
'L1A3':'Vigenere HEALTH',
'L2Q1':'DES message', 'L2Q2':'AES-128 message', 'L2Q3':'DES versus AES-256 timings',
'L2Q4':'Triple DES repeated-key issue', 'L2Q5':'AES-192 correction and all round steps',
'L2A1':'Five messages, four key sizes, five modes, CSV and graph',
'L2A2':'DES hex blocks', 'L2A3':'AES-256', 'L2A4':'DES CBC', 'L2A5':'AES CTR',
'L3Q1':'RSA-OAEP message', 'L3Q2':'ECC hybrid message', 'L3Q3':'ElGamal message',
'L3Q4':'RSA-2048/P-256 file benchmark', 'L3Q5':'DH key exchange and timings',
'L3A1':'ElGamal inconsistent public/private pair', 'L3A2':'ECC hybrid message (repeat)',
'L3A3':'Textbook RSA n=323,e=5,d=173', 'L3A4':'Healthcare EC-ElGamal performance',
'L3A5':'RSA versus EC-ElGamal versus ECC performance',
'L4Q1':'SecureCorp RSA/DH, signatures and KMS', 'L4Q2':'Healthcare Rabin centralized KMS',
'L4A1':'ElGamal DRM, expiry, revocation and key export', 'L4A2':'Weak RSA factorization attack',
'L5Q1':'Manual 32-bit DJB2-style hash',
'L5Q2':'Client/server integrity verification and tamper detection',
'L5Q3':'MD5/SHA-1/SHA-256 timing and collision experiment',
'L5A1':'Multipart socket transfer and integrity verification',
'L6Q1':'ElGamal and Schnorr signing and verification',
'L6Q2':'DH-style DSA signing and verification',
'L6Q3':'Client/server RSA-PSS signed message',
'L6A1':'CIA triad using RSA-OAEP, RSA-PSS, and SHA-256'
}


def roundtrip(label,plain,encrypt,decrypt):
    encrypted=encrypt(plain); recovered=decrypt(encrypted)
    print(label,'\n  plaintext:',plain,'\n  ciphertext:',encrypted,'\n  decrypted:',recovered)
    return encrypted,recovered


def symmetric_demo(message,key,algorithm,backend,mode='ECB',iv=None,nonce=b''):
    data=message.encode() if isinstance(message,str) else message
    options=dict(algorithm=algorithm,backend=backend,mode=mode,iv=iv,nonce=nonce)
    encrypted=s.crypt(data,key,**options); recovered=s.crypt(encrypted,key,decrypt=True,**options)
    assert recovered==data
    print('Algorithm:',algorithm,'mode:',mode,'key hex:',key.hex())
    print('Plaintext:',repr(data),'\nCiphertext hex:',encrypted.hex(),'\nRecovered:',repr(recovered))


def hybrid_demo(algorithm,message,backend):
    key=hybrid.keygen(algorithm,backend)
    encrypted=hybrid.encrypt(message.encode(),hybrid.public(key),backend)
    recovered=hybrid.decrypt(encrypted,key,backend)
    assert recovered==message.encode()
    print(algorithm,'encrypted envelope bytes:',len(encrypted),'recovered:',recovered.decode())


def run(question,backend='pure',repeats=3,full=False):
    print('\n===',question,QUESTIONS[question],'|',backend,'===')
    if question=='L1Q1':
        for label,a,b in [('Additive',1,20),('Multiplicative',15,0),('Affine',15,20)]:
            roundtrip(label,'I am learning information security',lambda text:c.affine(text,a,b,backend=backend),lambda text:c.affine(text,a,b,True,backend))
    elif question=='L1Q2':
        for key,auto in [('dollars',False),('H',True)]:
            roundtrip('Autokey' if auto else 'Vigenere','the house is being sold tonight',lambda text:c.vigenere(text,key,autokey=auto,backend=backend),lambda text:c.vigenere(text,key,True,auto,backend))
    elif question=='L1Q3':
        roundtrip('Playfair','The key is hidden under the door pad',lambda text:c.playfair(text,'GUIDANCE',backend=backend),lambda text:c.playfair(text,'GUIDANCE',True,backend))
        print('Decryption retains inserted X/Q and I/J ambiguity.')
    elif question=='L1Q4':
        print('Interpreting flattened key as rows [[3,3],[2,7]], column-vector multiplication.')
        roundtrip('Hill','We live in an insecure world',lambda text:c.hill(text,[[3,3],[2,7]],backend=backend),lambda text:c.hill(text,[[3,3],[2,7]],True,backend))
    elif question=='L1Q5':
        key=(ord('C')-ord('Y'))%26
        assert c.affine('yes',1,key)=='CIW'
        print('Known-plaintext attack; shift:',key,'tablet:',c.affine('XVIEWYWI',1,key,True))
    elif question=='L1Q6':
        matches=c.candidates('XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS','ab','GL',backend=backend)
        print('Enumerated 312 valid affine keys; matching (a,b,plaintext):',matches)
    elif question=='L1A1':
        for row in c.candidates('NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY',birthday=13,backend=backend): print(*row)
        print('Preserve / & punctuation; proximity to birthday orders guesses, does not prove a key.')
    elif question=='L1A2':
        try: c.infer_permutation('abcdefghi','CABDEHFGL')
        except ValueError as e: print('Literal manual:',e)
        print('Assuming L is typo for I, compatible zero-based permutations:',c.infer_permutation('abcdefghi','CABDEHFGI'))
        print('Chosen-plaintext attack. Corrected sample fits a 9-character permutation; block size is not uniquely proven from one sample.')
    elif question=='L1A3': roundtrip('Vigenere','Life is full of surprises',lambda text:c.vigenere(text,'HEALTH',backend=backend),lambda text:c.vigenere(text,'HEALTH',True,backend=backend))
    elif question=='L2Q1': symmetric_demo('Confidential Data',b'A1B2C3D4','DES',backend)
    elif question=='L2Q2': symmetric_demo('Sensitive Information',bytes.fromhex('0123456789ABCDEF'*2),'AES',backend)
    elif question=='L2Q3':
        message=b'Performance Testing of Encryption Algorithms'
        for algorithm,key in [('DES',b'A1B2C3D4'),('AES',bytes(range(32)))]:
            ciphertext,enc=benchmarks.measured(lambda:s.crypt(message,key,algorithm,'ECB',backend=backend),repeats)
            plain,dec=benchmarks.measured(lambda:s.crypt(ciphertext,key,algorithm,'ECB',True,backend=backend),repeats)
            assert plain==message
            print(algorithm,'key bits',len(key)*8,'median encryption ms',enc,'decryption ms',dec)
    elif question=='L2Q4':
        print('Literal hex key is 24 bytes but K1=K2=K3: EDE collapses to DES. Direct DES3 library API rejects it.')
        symmetric_demo('Classified Text',bytes.fromhex('1234567890ABCDEF'*3),'3DES',backend)
        print('Explicit replacement with distinct subkeys:')
        symmetric_demo('Classified Text',bytes.fromhex('0123456789ABCDEFFEDCBA987654321089ABCDEF01234567'),'3DES',backend)
    elif question=='L2Q5':
        print('Manual key has 16 hex bytes, not AES-192. Explicit repair: append FEDCBA9876543210 to obtain 24 bytes.')
        key=bytes.fromhex('FEDCBA9876543210'*3); steps=[]
        block=s.pad(b'Top Secret Data',16)
        encrypted=s.AES(key).encrypt(block,steps)
        print('Padded input:',block.hex())
        for label,state in steps: print(label,state)
        assert encrypted==s.crypt(b'Top Secret Data',key,mode='ECB',backend=backend)
        symmetric_demo('Top Secret Data',key,'AES',backend)
    elif question=='L2A1': benchmarks.symmetric_benchmark(backend,repeats,f'results/symmetric_{backend}.csv')
    elif question=='L2A2':
        for text in ['54686973206973206120636f6e666964656e7469616c206d657373616765','416e64207468697320697320746865207365636f6e6420626c6f636b']:
            symmetric_demo(bytes.fromhex(text),bytes.fromhex('A1B2C3D4E5F60708'),'DES',backend)
        print('These are multi-block messages; Mathematica appears to be a stray label.')
    elif question=='L2A3': symmetric_demo('Encryption Strength',bytes.fromhex('0123456789ABCDEF'*4),'AES',backend)
    elif question=='L2A4': symmetric_demo('Secure Communication',b'A1B2C3D4','DES',backend,'CBC',b'12345678')
    elif question=='L2A5': symmetric_demo('Cryptography Lab Exercise',bytes.fromhex('0123456789ABCDEF'*2),'AES',backend,'CTR',nonce=bytes.fromhex('0000000000000000'))
    elif question=='L3Q1':
        key=p.rsa_key(2048,backend); text=b'Asymmetric Encryption'
        ciphertext=p.oaep_encrypt(text,key,backend); recovered=p.oaep_decrypt(ciphertext,key,backend)
        assert recovered==text
        print('RSA-OAEP-SHA256 ciphertext:',ciphertext.hex(),'\nRecovered:',recovered.decode())
    elif question in ('L3Q2','L3A2'): hybrid_demo('ecc','Secure Transactions',backend)
    elif question in ('L3Q3','L3A1'):
        modulus,g,x=7919,2,2999; h=pow(g,x,modulus)
        if question=='L3A1':
            print('Manual h=6465 is inconsistent: pow(2,2999,7919)=3868. Correcting h to 3868, retaining private x.')
        message=b'Confidential Data' if question=='L3Q3' else b'Asymmetric Algorithms'
        ciphertext=p.elgamal_encrypt(message,modulus,g,h,backend)
        recovered=bytes(p.elgamal_decrypt(ciphertext,modulus,x,backend)); assert recovered==message
        print('Public key:',(modulus,g,h),'\nCiphertext:',ciphertext,'\nRecovered:',recovered.decode())
    elif question in ('L3Q4','L3A4','L3A5'):
        algorithms=('rsa','ecc') if question=='L3Q4' else ('ec-elgamal',) if question=='L3A4' else ('rsa','ec-elgamal','ecc')
        sizes=(1048576,10485760) if question=='L3Q4' and full else (1024,10240)
        if question=='L3Q4' and not full: print('Quick sizes 1 KiB/10 KiB; use --full for required 1 MiB/10 MiB.')
        benchmarks.file_benchmark(backend,sizes,repeats,algorithms,f'results/{question}_{backend}.csv')
    elif question=='L3Q5':
        start=time.perf_counter_ns(); a,b=secrets.randbelow(p.DH_P-4)+2,secrets.randbelow(p.DH_P-4)+2
        A,B=p.modexp(2,a,p.DH_P,backend),p.modexp(2,b,p.DH_P,backend); keytime=(time.perf_counter_ns()-start)/1e6
        start=time.perf_counter_ns(); ka=p.dh_shared(a,B,backend=backend); kb=p.dh_shared(b,A,backend=backend); elapsed=(time.perf_counter_ns()-start)/1e6
        assert ka==kb
        print('Group14 2048-bit DH matched. Both peers combined: keygen ms',keytime,'exchange ms',elapsed)
    elif question=='L3A3':
        message=b'Cryptographic Protocols'; ciphertext=p.raw_rsa(message,323,5,backend)
        recovered=bytes(p.raw_rsa(ciphertext,323,173,backend)); assert recovered==message
        print('n=17*19; phi=288; 5*173 mod 288 =',5*173%288,'\nCiphertext:',ciphertext,'\nRecovered:',recovered.decode())
    elif question=='L4Q1': services.securecorp(backend)
    elif question=='L4Q2': services.healthcare(backend)
    elif question=='L4A1': services.drm(backend)
    elif question=='L4A2':
        n=1009*1013; e=65537; text=b'Logistics'; ciphertext=p.raw_rsa(text,n,e,backend)
        for method in ['trial','fermat','rho']:
            start=time.perf_counter_ns(); u,v=p.factor(n,method); d=pow(e,-1,(u-1)*(v-1)); recovered=bytes(p.raw_rsa(ciphertext,n,d,backend))
            assert recovered==text
            print(method,'p,q,d:',u,v,d,'recovered:',recovered,'time ms:',(time.perf_counter_ns()-start)/1e6)
        print('Small/close primes suffice for this attack; no partial private-key bits were specified in the manual.')
    elif question=='L5Q1':
        text='Information Security'
        print('Input:',text,'\n32-bit hash decimal:',hashing.manual_hash(text),'\nhex:',f'{hashing.manual_hash(text):08x}')
    elif question in ('L5Q2','L5A1'):
        left,right=socket.socketpair(); message=b'Integrity protected message'
        parts=[message] if question=='L5Q2' else [message[:8],message[8:17],message[17:]]
        def server():
            request=hashing.receive_packet(right)
            rebuilt=b''.join(bytes.fromhex(part) for part in request['parts'])
            hashing.send_packet(right,{'sha256':hashing.digest(rebuilt),'bytes':len(rebuilt)})
            right.close()
        worker=threading.Thread(target=server); worker.start()
        hashing.send_packet(left,{'parts':[part.hex() for part in parts]})
        response=hashing.receive_packet(left); worker.join(); left.close()
        local=hashing.digest(message)
        print('parts:',len(parts),'server hash:',response['sha256'],'local hash:',local,'verified:',response['sha256']==local)
        tampered=message+b'!'
        print('tampered local hash:',hashing.digest(tampered),'verified:',response['sha256']==hashing.digest(tampered))
    elif question=='L5Q3':
        values=hashing.random_dataset(100,32)
        for row in hashing.benchmark_hashes(values): print(row)
        print('Zero observed collisions does not prove collision resistance; 100 samples are far below birthday bounds.')
    elif question=='L6Q1':
        message=b'Approved document'
        x,y=ds.elgamal_keygen(); signature=ds.elgamal_sign(message,x)
        print('ElGamal signature:',signature,'valid:',ds.elgamal_verify(message,signature,y),'tampered:',ds.elgamal_verify(message+b'!',signature,y))
        x,y=ds.schnorr_keygen(); signature=ds.schnorr_sign(message,x)
        print('Schnorr signature:',signature,'valid:',ds.schnorr_verify(message,signature,y),'tampered:',ds.schnorr_verify(message+b'!',signature,y))
    elif question=='L6Q2':
        message=b'Diffie-Hellman family signature'; x,y=ds.dsa_keygen(); signature=ds.dsa_sign(message,x)
        print('Plain DH is key agreement, not a signature. DSA uses DH-style group math.')
        print('DSA signature:',signature,'valid:',ds.dsa_verify(message,signature,y),'tampered:',ds.dsa_verify(message+b'!',signature,y))
    elif question=='L6Q3':
        private=p.rsa_key(2048,backend); public={'n':private['n'],'e':private['e']}
        message=b'Signed client request'; signature=p.sign(message,private,backend)
        left,right=socket.socketpair()
        def signed_server():
            request=hashing.receive_packet(right); data=bytes.fromhex(request['message']); sig=bytes.fromhex(request['signature'])
            hashing.send_packet(right,{'valid':p.verify(data,sig,public,backend)}); right.close()
        worker=threading.Thread(target=signed_server); worker.start()
        hashing.send_packet(left,{'message':message.hex(),'signature':signature.hex()})
        print('server response:',hashing.receive_packet(left)); worker.join(); left.close()
    elif question=='L6A1':
        private= p.rsa_key(2048,backend); public={'n':private['n'],'e':private['e']}; message=b'CIA demonstration'
        ciphertext=p.oaep_encrypt(message,public,backend); signature=p.sign(ciphertext,private,backend)
        print('Confidentiality: RSA-OAEP ciphertext bytes',len(ciphertext))
        print('Integrity/authenticity: RSA-PSS over ciphertext valid =',p.verify(ciphertext,signature,public,backend))
        recovered=p.oaep_decrypt(ciphertext,private,backend); print('Recovered:',recovered.decode(),'SHA-256:',hashing.digest(recovered))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('question',nargs='?',choices=QUESTIONS)
    parser.add_argument('--backend',choices=['pure','lib'],default='pure')
    parser.add_argument('--list',action='store_true'); parser.add_argument('--all',action='store_true')
    parser.add_argument('--repeats',type=int,default=3); parser.add_argument('--full',action='store_true')
    args=parser.parse_args()
    if args.list:
        for key,value in QUESTIONS.items(): print(key,value)
    elif args.all:
        for key in QUESTIONS: run(key,args.backend,args.repeats,args.full)
    elif args.question: run(args.question,args.backend,args.repeats,args.full)
    else:
        for key,value in QUESTIONS.items(): print(key,value)
        question=input('Question ID: ').strip().upper()
        if question not in QUESTIONS: parser.error('Unknown question ID')
        run(question,args.backend,args.repeats,args.full)


if __name__=='__main__': main()
