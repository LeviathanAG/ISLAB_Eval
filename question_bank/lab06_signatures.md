# Ten question variations per algorithm - Lab06 Signatures

Each group has ten common examiner variations. The referenced file contains the reusable implementation and its input rules.

## RSA-PSS

Use: `signatures.py`. Core requirement: RSA private/public keys and SHA-256.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid RSA private/public keys and SHA-256; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## ElGamal signature

Use: `signatures.py`. Core requirement: prime group and never-reused nonce.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid prime group and never-reused nonce; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Schnorr

Use: `signatures.py`. Core requirement: q-order subgroup and random nonce.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid q-order subgroup and random nonce; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## DSA/DH-family signature

Use: `signatures.py`. Core requirement: p,q,g group and random nonce.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid p,q,g group and random nonce; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Signed client/server

Use: `demo_all.py`. Core requirement: framing, public-key distribution and verification.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid framing, public-key distribution and verification; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

