import hashlib, hmac

message, key = b'amount=100', b'shared-secret'
print('hash:', hashlib.sha256(message).hexdigest())
print('HMAC:', hmac.new(key, message, hashlib.sha256).hexdigest())
