import hashlib, json, time

log = []
def audit(action):
    previous = log[-1]['hash'] if log else ''
    entry = {'time': time.time(), 'action': action, 'previous': previous}
    entry['hash'] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest(); log.append(entry)
audit('generate key'); audit('distribute public key'); audit('revoke key')
print(*log, sep='\n')
