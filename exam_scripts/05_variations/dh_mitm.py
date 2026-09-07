p, g = 23, 5; alice_private, bob_private = 6, 15; eve_left, eve_right = 7, 9
alice_public, bob_public = pow(g, alice_private, p), pow(g, bob_private, p)
alice_secret = pow(pow(g, eve_left, p), alice_private, p)
eve_alice_secret = pow(alice_public, eve_left, p)
bob_secret = pow(pow(g, eve_right, p), bob_private, p)
eve_bob_secret = pow(bob_public, eve_right, p)
print('Alice/Eve:', alice_secret, eve_alice_secret, 'Bob/Eve:', bob_secret, eve_bob_secret)
print('Authenticate DH public values to prevent this.')
