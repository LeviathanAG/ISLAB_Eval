import time

keys = [{'version': 1, 'created': time.time(), 'active': True}]
keys[-1]['active'] = False
keys.append({'version': 2, 'created': time.time(), 'active': True})
print(keys)
