import hashlib, hmac, secrets

key, message = secrets.token_bytes(32), b'authenticated message'
tag = hmac.new(key, message, hashlib.sha256).digest(); changed = message + b'!'
print('original valid:', hmac.compare_digest(tag, hmac.new(key, message, hashlib.sha256).digest()))
print('changed valid:', hmac.compare_digest(tag, hmac.new(key, changed, hashlib.sha256).digest()))
