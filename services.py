"""Lab 4 centralized KMS and DRM: encrypted SQLite keys, API tokens, expiry and audit.
Runnable demos use temporary databases. Optional HTTPS API requires your TLS certificate.
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import tempfile
import time
from pathlib import Path
import hybrid
from public_key import (DH_P, dh_shared, modexp, sign, verify, hkdf, seal, unseal)


class KeyService:
    def __init__(self,path,master,backend='pure'):
        if len(master)!=32: raise ValueError('Storage master key must be 32 random bytes, stored separately')
        self.master,self.backend=master,backend
        self.db=sqlite3.connect(path)
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, token TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS keys(owner TEXT, version INTEGER, algorithm TEXT, public TEXT,
          private BLOB, expires REAL, active INTEGER, PRIMARY KEY(owner,version));
        CREATE TABLE IF NOT EXISTS content(id TEXT PRIMARY KEY, creator TEXT, key_owner TEXT,
          version INTEGER, ciphertext BLOB);
        CREATE TABLE IF NOT EXISTS grants(content TEXT, customer TEXT, expires REAL,
          PRIMARY KEY(content,customer));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp REAL, actor TEXT,
          action TEXT, target TEXT, detail TEXT, previous TEXT, mac TEXT);
        ''')
        self.db.commit()
        # ponytail: one process owns this SQLite connection; add a worker queue for concurrency.

    def close(self): self.db.close()

    def log(self,actor,action,target,detail=''):
        row=self.db.execute('SELECT mac FROM audit ORDER BY id DESC LIMIT 1').fetchone()
        previous=row[0] if row else ''
        stamp=time.time()
        mac=hmac.new(hkdf(self.master,info=b'audit',length=32),hybrid.encode([stamp,actor,action,target,detail,previous]),hashlib.sha256).hexdigest()
        self.db.execute('INSERT INTO audit(timestamp,actor,action,target,detail,previous,mac) VALUES(?,?,?,?,?,?,?)',(stamp,actor,action,target,detail,previous,mac))
        self.db.commit()

    def check_audit(self):
        previous=''
        for stamp,actor,action,target,detail,prev,mac in self.db.execute('SELECT timestamp,actor,action,target,detail,previous,mac FROM audit ORDER BY id'):
            expected=hmac.new(hkdf(self.master,info=b'audit',length=32),hybrid.encode([stamp,actor,action,target,detail,prev]),hashlib.sha256).hexdigest()
            if prev!=previous or not hmac.compare_digest(expected,mac): return False
            previous=mac
        return True  # An external checkpoint is needed to detect tail deletion.

    def bootstrap(self,name='admin'):
        if self.db.execute('SELECT 1 FROM users LIMIT 1').fetchone(): raise PermissionError('Already initialized')
        return self._user(name,'admin')

    def _user(self,name,role):
        if role not in ('admin','facility','creator','customer','system'): raise ValueError('Invalid role')
        token=secrets.token_hex(32)
        self.db.execute('INSERT INTO users VALUES(?,?,?)',(name,hashlib.sha256(token.encode()).hexdigest(),role))
        self.db.commit(); self.log(name,'create-user',name,role)
        return token

    def auth(self,token):
        if not isinstance(token,str): raise PermissionError('Missing API token')
        digest=hashlib.sha256(token.encode()).hexdigest()
        row=self.db.execute('SELECT name,role FROM users WHERE token=?',(digest,)).fetchone()
        if not row:
            self.log('unknown','denied','authentication'); raise PermissionError('Invalid API token')
        return row

    def require(self,token,roles=(),owner=None):
        name,role=self.auth(token)
        if role!='admin' and role not in roles and name!=owner:
            self.log(name,'denied',owner or str(roles)); raise PermissionError('Access denied')
        return name,role

    def add_user(self,token,name,role):
        self.require(token,('admin',)); return self._user(name,role)

    def generate(self,token,owner,algorithm='rabin',bits=1024,lifetime=365*86400):
        actor,_=self.require(token,('admin',))
        if lifetime<=0: raise ValueError('Lifetime must be positive')
        if not self.db.execute('SELECT 1 FROM users WHERE name=?',(owner,)).fetchone() and owner!='master': raise ValueError('Unknown owner')
        key=hybrid.keygen(algorithm,self.backend,bits)
        version=self.db.execute('SELECT COALESCE(MAX(version),0)+1 FROM keys WHERE owner=?',(owner,)).fetchone()[0]
        context=f'{owner}:{version}'.encode()
        encrypted=seal(hybrid.encode(key),self.master,self.backend,context)
        with self.db:
            self.db.execute('UPDATE keys SET active=0 WHERE owner=?',(owner,))
            self.db.execute('INSERT INTO keys VALUES(?,?,?,?,?,?,1)',(owner,version,algorithm,hybrid.encode(hybrid.public(key)).decode(),encrypted,time.time()+lifetime))
        self.log(actor,'generate/renew',owner,str(version)); return version

    def get(self,token,owner,private=False,version=None):
        actor,_=self.require(token,('admin',) if private else ('facility','creator','customer','system'),owner if private else None)
        if version is None:
            row=self.db.execute('SELECT version,public,private,expires,active FROM keys WHERE owner=? ORDER BY version DESC LIMIT 1',(owner,)).fetchone()
        else: row=self.db.execute('SELECT version,public,private,expires,active FROM keys WHERE owner=? AND version=?',(owner,version)).fetchone()
        if not row or not row[4] or row[3]<=time.time():
            self.log(actor,'denied-key',owner); raise PermissionError('Key missing, expired or revoked')
        self.log(actor,'distribute-private' if private else 'distribute-public',owner,str(row[0]))
        return json.loads(unseal(row[2],self.master,self.backend,f'{owner}:{row[0]}'.encode())) if private else json.loads(row[1])

    def revoke(self,token,owner):
        actor,_=self.require(token,('admin',))
        self.db.execute('UPDATE keys SET active=0 WHERE owner=?',(owner,)); self.db.commit()
        self.log(actor,'revoke',owner)

    def renew_due(self,token,lifetime=365*86400):
        self.require(token,('admin',))
        rows=self.db.execute('SELECT owner,algorithm,public FROM keys WHERE active=1 AND expires<=?',(time.time(),)).fetchall()
        for owner,algorithm,pub in rows:
            pub=json.loads(pub); bits=pub.get('n',pub.get('p',0)).bit_length() or 256
            self.generate(token,owner,algorithm,bits,lifetime)
        return len(rows)

    def upload(self,token,content_id,data):
        actor,_=self.require(token,('creator',))
        pub=self.get(token,'master')
        version=self.db.execute("SELECT version FROM keys WHERE owner='master' AND active=1").fetchone()[0]
        ciphertext=hybrid.encrypt(data,pub,self.backend,content_id)
        self.db.execute('INSERT INTO content VALUES(?,?,?,?,?)',(content_id,actor,'master',version,ciphertext)); self.db.commit()
        self.log(actor,'upload',content_id); return ciphertext

    def grant(self,token,content_id,customer,seconds):
        if seconds<=0: raise ValueError('Access duration must be positive')
        row=self.db.execute('SELECT creator FROM content WHERE id=?',(content_id,)).fetchone()
        if not row: raise ValueError('Unknown content')
        actor,_=self.require(token,('admin',),row[0])
        if not self.db.execute("SELECT 1 FROM users WHERE name=? AND role='customer'",(customer,)).fetchone(): raise ValueError('Unknown customer')
        self.db.execute('INSERT OR REPLACE INTO grants VALUES(?,?,?)',(content_id,customer,time.time()+seconds)); self.db.commit()
        self.log(actor,'grant',content_id,customer)

    def revoke_access(self,token,content_id,customer):
        row=self.db.execute('SELECT creator FROM content WHERE id=?',(content_id,)).fetchone()
        if not row: raise ValueError('Unknown content')
        actor,_=self.require(token,('admin',),row[0])
        self.db.execute('DELETE FROM grants WHERE content=? AND customer=?',(content_id,customer)); self.db.commit()
        self.log(actor,'revoke-access',content_id,customer)

    def _licensed(self,token,content_id):
        actor,role=self.auth(token)
        row=self.db.execute('SELECT creator,key_owner,version,ciphertext FROM content WHERE id=?',(content_id,)).fetchone()
        if not row: raise ValueError('Unknown content')
        grant=self.db.execute('SELECT expires FROM grants WHERE content=? AND customer=?',(content_id,actor)).fetchone()
        if role!='admin' and actor!=row[0] and (not grant or grant[0]<=time.time()):
            self.log(actor,'denied-content',content_id); raise PermissionError('No active content license')
        keyrow=self.db.execute('SELECT private,expires,active FROM keys WHERE owner=? AND version=?',(row[1],row[2])).fetchone()
        if not keyrow or not keyrow[2] or keyrow[1]<=time.time(): raise PermissionError('Content master key expired or revoked')
        private=json.loads(unseal(keyrow[0],self.master,self.backend,f'{row[1]}:{row[2]}'.encode()))
        return actor,row,private

    def read_content(self,token,content_id):
        actor,row,key=self._licensed(token,content_id)
        result=hybrid.decrypt(row[3],key,self.backend,content_id)
        self.log(actor,'read-content',content_id); return result

    def export_master_for_customer(self,token,content_id):
        """Literal manual requirement. Recipient can now decrypt ALL content for this key version.
        Revocation cannot erase an exported key. Prefer read_content for enforceable API checks.
        """
        actor,row,key=self._licensed(token,content_id)
        self.log(actor,'export-master-NONREVOCABLE',content_id); return key


def securecorp(backend='pure'):
    with tempfile.TemporaryDirectory() as directory:
        svc=KeyService(Path(directory)/'kms.db',secrets.token_bytes(32),backend)
        admin=svc.bootstrap()
        tokens={name:svc.add_user(admin,name,'system') for name in ['Finance','HR','SupplyChain']}
        for name in tokens: svc.generate(admin,name,'rsa',2048)
        sender,receiver='Finance','HR'
        signing=svc.get(tokens[sender],sender,True)
        recipient=svc.get(tokens[receiver],receiver,True)
        # The authenticated directory pins identity public keys before the handshake.
        pinned_sender=svc.get(tokens[receiver],sender)
        pinned_recipient=svc.get(tokens[sender],receiver)
        a,b=secrets.randbelow(DH_P-4)+2,secrets.randbelow(DH_P-4)+2
        A,B=modexp(2,a,DH_P,backend),modexp(2,b,DH_P,backend)
        transcript=hybrid.encode(dict(sender=sender,receiver=receiver,A=A,B=B,nonce=secrets.token_hex(16)))
        sa,sb=sign(transcript,signing,backend),sign(transcript,recipient,backend)
        assert verify(transcript,sa,pinned_sender,backend) and verify(transcript,sb,pinned_recipient,backend)
        ka=hkdf(dh_shared(a,B,backend=backend).to_bytes(256,'big'),info=transcript)
        kb=hkdf(dh_shared(b,A,backend=backend).to_bytes(256,'big'),info=transcript)
        assert ka==kb
        document=b'Finance report: approved procurement budget.'
        signed=hybrid.encode(dict(document=document.hex(),signature=sign(document,signing,backend).hex()))
        # RSA-OAEP hybrid protects the document; authenticated DH protects the channel.
        packet=seal(hybrid.encrypt(signed,pinned_recipient,backend),ka,backend,transcript)
        recovered=json.loads(hybrid.decrypt(unseal(packet,kb,backend,transcript),recipient,backend))
        assert verify(bytes.fromhex(recovered['document']),bytes.fromhex(recovered['signature']),pinned_sender,backend)
        print('Authenticated RSA-PSS/DH channel and RSA-OAEP document:',bytes.fromhex(recovered['document']).decode())
        svc.add_user(admin,'NewSubsystem','system'); svc.generate(admin,'NewSubsystem','rsa',2048)
        svc.revoke(admin,'HR')
        try: svc.get(tokens['HR'],'HR',True)
        except PermissionError: print('Revoked HR key distribution denied; new subsystem enrolled.')
        else: raise AssertionError('Revocation failed')
        assert svc.check_audit(); svc.close()


def healthcare(backend='pure',bits=1024):
    with tempfile.TemporaryDirectory() as directory:
        svc=KeyService(Path(directory)/'kms.db',secrets.token_bytes(32),backend); admin=svc.bootstrap()
        hospital=svc.add_user(admin,'Hospital','facility'); clinic=svc.add_user(admin,'Clinic','facility')
        svc.generate(admin,'Hospital','rabin',bits); svc.generate(admin,'Clinic','rabin',bits)
        record=b'Patient 42: follow-up scheduled'
        c=hybrid.encrypt(record,svc.get(hospital,'Hospital'),backend)
        assert hybrid.decrypt(c,svc.get(hospital,'Hospital',True),backend)==record
        try: svc.get(clinic,'Hospital',True)
        except PermissionError: print('Cross-facility private-key request denied.')
        else: raise AssertionError('Access control failed')
        svc.revoke(admin,'Clinic'); svc.generate(admin,'Clinic','rabin',bits)
        # Advance expiry in the fixture so the automatic-renewal path can be demonstrated now.
        svc.db.execute("UPDATE keys SET expires=? WHERE owner='Hospital' AND active=1",(time.time()-1,)); svc.db.commit()
        assert svc.renew_due(admin)==1
        assert svc.check_audit()
        print('Rabin record round-trip, revocation, replacement, scheduled-renewal callback, encrypted storage and audit passed.')
        svc.close()


def drm(backend='pure',bits=2048):
    with tempfile.TemporaryDirectory() as directory:
        svc=KeyService(Path(directory)/'kms.db',secrets.token_bytes(32),backend); admin=svc.bootstrap()
        creator=svc.add_user(admin,'Author','creator'); customer=svc.add_user(admin,'Reader','customer')
        svc.generate(admin,'master','elgamal',bits,2*365*86400)
        ciphertext=svc.upload(creator,'book',b'Licensed book contents')
        svc.grant(creator,'book','Reader',3600)
        assert svc.read_content(customer,'book')==b'Licensed book contents'
        exported=svc.export_master_for_customer(customer,'book')
        svc.revoke_access(creator,'book','Reader')
        try: svc.read_content(customer,'book')
        except PermissionError: print('Revoked customer denied by API.')
        else: raise AssertionError('Revocation failed')
        assert hybrid.decrypt(ciphertext,exported,backend,'book')==b'Licensed book contents'
        print('Manual master-key export demonstrated: copied key STILL decrypts offline after revocation.')
        svc.revoke(admin,'master'); svc.generate(admin,'master','elgamal',bits,2*365*86400)
        svc.db.execute("UPDATE keys SET expires=? WHERE owner='master' AND active=1",(time.time()-1,)); svc.db.commit()
        assert svc.renew_due(admin,2*365*86400)==1
        assert svc.check_audit(); svc.close()


def serve(args):
    """Single-process HTTPS JSON API. CA-trusted/pinned certificate required at client."""
    import ssl
    from http.server import HTTPServer,BaseHTTPRequestHandler
    master=Path(args.master_file).read_bytes()
    svc=KeyService(args.database,master,args.backend)
    allowed={'add_user','generate','get','revoke','upload','grant','revoke_access','read_content','export_master_for_customer'}
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=2*1024*1024: raise ValueError('Body must be 1..2 MiB')
                token=self.headers.get('Authorization','').removeprefix('Bearer ')
                action=self.path.removeprefix('/')
                if action not in allowed: raise ValueError('Unknown action')
                request=json.loads(self.rfile.read(length))
                if action=='upload': request['data']=base64.b64decode(request['data'],validate=True)
                result=getattr(svc,action)(token,**request)
                if isinstance(result,bytes): result={'base64':base64.b64encode(result).decode()}
                response=hybrid.encode({'result':result}); status=200
            except (ValueError,PermissionError,TypeError,KeyError,sqlite3.Error):
                response=b'{"error":"request rejected"}'; status=400
            self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(response))); self.end_headers(); self.wfile.write(response)
        def log_message(self,*args): pass  # Application audit records events without bearer tokens.
    server=HTTPServer(('127.0.0.1',args.port),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert,args.tls_key); server.socket=ctx.wrap_socket(server.socket,server_side=True)
    # Renewal runs even without incoming API calls. Revoked keys remain revoked.
    admin_token=args.renew_token_file and Path(args.renew_token_file).read_text().strip()
    server.timeout=1
    print(f'HTTPS API listening on 127.0.0.1:{args.port}; Ctrl-C to stop')
    try:
        while True:
            server.handle_request()
            if admin_token: svc.renew_due(admin_token,args.lifetime_days*86400)
    finally: server.server_close(); svc.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('scenario',choices=['securecorp','healthcare','drm','init','serve'])
    p.add_argument('--backend',choices=['pure','lib'],default='lib')
    p.add_argument('--bits',type=int)
    p.add_argument('--database',default='kms.sqlite'); p.add_argument('--master-file',default='kms.master')
    p.add_argument('--cert'); p.add_argument('--tls-key'); p.add_argument('--port',type=int,default=8443)
    p.add_argument('--renew-token-file'); p.add_argument('--lifetime-days',type=int,default=365)
    a=p.parse_args()
    try:
        if a.scenario=='securecorp': securecorp(a.backend)
        elif a.scenario=='healthcare': healthcare(a.backend,a.bits or 1024)
        elif a.scenario=='drm': drm(a.backend,a.bits or 2048)
        elif a.scenario=='init':
            if Path(a.database).exists(): raise ValueError('Use a new database path')
            master=secrets.token_bytes(32); hybrid.write_new(a.master_file,master,True)
            svc=KeyService(a.database,master,a.backend); token=svc.bootstrap(); svc.close()
            Path(a.database).chmod(0o600)
            hybrid.write_new(a.master_file+'.admin-token',token.encode(),True)
            print('Initialized. Admin token saved to',a.master_file+'.admin-token','(keep separate from database).')
        else:
            if not a.cert or not a.tls_key: raise ValueError('HTTPS requires --cert and --tls-key; do not disable client certificate verification')
            serve(a)
    except (ValueError,PermissionError,OSError) as e: p.error(str(e))


if __name__=='__main__': main()
