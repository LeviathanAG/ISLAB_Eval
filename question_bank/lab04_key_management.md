# Ten question variations per algorithm - Lab04 Key Management

Each group has ten common examiner variations. The referenced file contains the reusable implementation and its input rules.

## RSA+DH secure channel

Use: `key_manager_patterns.py + Lab 3 files`. Core requirement: identity keys, ephemeral DH, KDF and authenticated cipher.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid identity keys, ephemeral DH, KDF and authenticated cipher; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Rabin

Use: `rabin.py`. Core requirement: Blum primes and four-root disambiguation.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid Blum primes and four-root disambiguation; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Central key management

Use: `key_manager_patterns.py`. Core requirement: authentication, wrapping, version, expiry, revocation and audit.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid authentication, wrapping, version, expiry, revocation and audit; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Weak RSA factorization

Use: `weak_rsa_attack.py`. Core requirement: small/close primes.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid small/close primes; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

