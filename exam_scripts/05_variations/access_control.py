permissions = {'doctor': {'read', 'write'}, 'nurse': {'read'}, 'guest': set()}
def rbac(role, action): return action in permissions.get(role, set())
def bell_lapadula(clearance, classification, action):
    return clearance >= classification if action == 'read' else clearance <= classification
print('doctor write:', rbac('doctor', 'write')); print('guest read:', rbac('guest', 'read'))
print('level 2 reads level 1:', bell_lapadula(2, 1, 'read'))
print('level 2 writes level 1:', bell_lapadula(2, 1, 'write'))
