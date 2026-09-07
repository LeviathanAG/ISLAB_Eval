"""Measured CSVs and plots, with round-trip validation outside timed sections."""
import argparse
import csv
import statistics
import time
from pathlib import Path
import secrets
import symmetric
import hybrid


def measured(call,repeats):
    if repeats<1: raise ValueError('Repeats must be positive')
    values=[]; result=None
    for _ in range(repeats):
        start=time.perf_counter_ns(); result=call(); values.append((time.perf_counter_ns()-start)/1e6)
    return result,statistics.median(values)


def save(rows,path):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    print('Saved',path)


def plot(rows,path,backend):
    totals={}
    for row in rows:
        label=row['algorithm']+' '+row.get('mode','')
        totals.setdefault(label,[]).append(row['encrypt_ms'])
    labels=list(totals); values=[statistics.mean(totals[k]) for k in labels]
    if backend=='lib':
        import matplotlib
        matplotlib.use('Agg')
        from matplotlib import pyplot as plt
        fig,ax=plt.subplots(figsize=(12,6)); ax.bar(labels,values); ax.set_ylabel('Mean of per-message median encryption time (ms)')
        ax.tick_params(axis='x',rotation=75); fig.tight_layout(); fig.savefig(path); plt.close(fig)
    else:
        # Standard SVG is readable in any browser and requires no plotting dependency.
        from html import escape
        maximum=max(values) or 1; width=1000; height=40*len(labels)+50
        lines=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">', '<rect width="100%" height="100%" fill="white"/>']
        for i,(label,value) in enumerate(zip(labels,values)):
            y=35+40*i
            lines += [f'<text x="5" y="{y}" font-size="14">{escape(label)}</text>',f'<rect x="170" y="{y-15}" width="{650*value/maximum}" height="22" fill="steelblue"/>',f'<text x="{180+650*value/maximum}" y="{y}" font-size="12">{value:.4f} ms</text>']
        lines.append('</svg>'); Path(path).write_text('\n'.join(lines))
    print('Saved',path)


def symmetric_benchmark(backend='lib',repeats=20,output='results/symmetric.csv'):
    messages=[b'Hello',b'Confidential Data',b'Performance Testing of Encryption Algorithms',b'A'*128,b'B'*1024]
    rows=[]
    for algorithm,size in [('DES',8),('AES',16),('AES',24),('AES',32)]:
        key=secrets.token_bytes(size)  # Reused for five messages as requested; IV/nonce is fresh per message.
        bs=8 if algorithm=='DES' else 16
        for mode in ['ECB','CBC','CFB','OFB','CTR']:
            for index,message in enumerate(messages):
                options=dict(algorithm=algorithm,mode=mode,iv=secrets.token_bytes(bs),nonce=secrets.token_bytes(bs//2),backend=backend)
                c,enc=measured(lambda:symmetric.crypt(message,key,**options),repeats)
                plain,dec=measured(lambda:symmetric.crypt(c,key,decrypt=True,**options),repeats)
                assert plain==message
                rows.append(dict(backend=backend,algorithm=algorithm+str(size*8),mode=mode,message=index+1,bytes=len(message),repeats=repeats,encrypt_ms=enc,decrypt_ms=dec))
    save(rows,output); plot(rows,str(Path(output).with_suffix('.svg')),backend); return rows


def file_benchmark(backend='lib',sizes=(1024,10240,1048576,10485760),repeats=3,algorithms=('rsa','ecc','ec-elgamal'),output='results/files.csv'):
    rows=[]
    for algorithm in algorithms:
        key,key_ms=measured(lambda:hybrid.keygen(algorithm,backend,2048),repeats)
        pub=hybrid.public(key)
        for size in sizes:
            if size<0: raise ValueError('Size cannot be negative')
            message=secrets.token_bytes(size)
            c,enc=measured(lambda:hybrid.encrypt(message,pub,backend),repeats)
            plain,dec=measured(lambda:hybrid.decrypt(c,key,backend),repeats)
            assert plain==message
            rows.append(dict(backend=backend,algorithm=algorithm,bytes=size,repeats=repeats,keygen_ms=key_ms,encrypt_ms=enc,decrypt_ms=dec,overhead_bytes=len(c)-size,public_json_bytes=len(hybrid.encode(pub)),private_json_bytes=len(hybrid.encode(key))))
            print(f'{algorithm} {size} bytes: enc={enc:.3f} ms dec={dec:.3f} ms; verified',flush=True)
    save(rows,output); return rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind',choices=['symmetric','files'])
    p.add_argument('--backend',choices=['pure','lib'],default='lib')
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--sizes',default='1024,10240,1048576,10485760')
    p.add_argument('--algorithms',default='rsa,ecc,ec-elgamal')
    p.add_argument('--output')
    a=p.parse_args()
    try:
        if a.kind=='symmetric': symmetric_benchmark(a.backend,a.repeats,a.output or f'results/symmetric_{a.backend}.csv')
        else: file_benchmark(a.backend,tuple(map(int,a.sizes.split(','))),a.repeats,tuple(a.algorithms.split(',')),a.output or f'results/files_{a.backend}.csv')
    except ValueError as e: p.error(str(e))


if __name__=='__main__': main()
