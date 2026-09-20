# Ten question variations per algorithm - Lab03 Public Key

Each group has ten common examiner variations. The referenced file contains the reusable implementation and its input rules.

## RSA

Use: `rsa.py`. Core requirement: (n,e)/(n,d), OAEP for real encryption.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid (n,e)/(n,d), OAEP for real encryption; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Diffie-Hellman

Use: `diffie_hellman.py`. Core requirement: p,g, private exponents and validated public values.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid p,g, private exponents and validated public values; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## ElGamal encryption

Use: `elgamal.py`. Core requirement: p,g,h and fresh random k.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid p,g,h and fresh random k; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## ECC/ECDH hybrid

Use: `ecc_hybrid.py`. Core requirement: P-256 keys, HKDF and AES-GCM.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid P-256 keys, HKDF and AES-GCM; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

