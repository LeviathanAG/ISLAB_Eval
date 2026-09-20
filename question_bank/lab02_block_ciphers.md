# Ten question variations per algorithm - Lab02 Block Ciphers

Each group has ten common examiner variations. The referenced file contains the reusable implementation and its input rules.

## AES

Use: `aes_from_scratch.py or library_ciphers.py`. Core requirement: 16/24/32-byte key and a mode.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid 16/24/32-byte key and a mode; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## DES

Use: `des_from_scratch.py or library_ciphers.py`. Core requirement: 8-byte key and 8-byte blocks.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid 8-byte key and 8-byte blocks; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Triple DES

Use: `library_ciphers.py`. Core requirement: 16/24-byte non-degenerate key.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid 16/24-byte non-degenerate key; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## ECB/CBC/CTR/GCM modes

Use: `library_ciphers.py`. Core requirement: valid IV or unique nonce.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid valid IV or unique nonce; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

