# Ten question variations per algorithm - Lab05 Hashing

Each group has ten common examiner variations. The referenced file contains the reusable implementation and its input rules.

## Manual 32-bit hash

Use: `hash_functions.py`. Core requirement: initial 5381 and 32-bit mask.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid initial 5381 and 32-bit mask; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## MD5

Use: `hash_functions.py`. Core requirement: arbitrary bytes, 128-bit output.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid arbitrary bytes, 128-bit output; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## SHA-1

Use: `hash_functions.py`. Core requirement: arbitrary bytes, 160-bit output.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid arbitrary bytes, 160-bit output; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## SHA-256

Use: `hash_functions.py`. Core requirement: arbitrary bytes, 256-bit output.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid arbitrary bytes, 256-bit output; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

## Socket integrity

Use: `integrity_server.py + integrity_client.py`. Core requirement: message framing and local/remote digest comparison.

1. Encrypt/sign/hash the supplied message with changed inputs; print every input, result, and recovered/verified value.
2. Add decryption or verification and prove round-trip correctness with an assertion.
3. Reject an invalid message framing and local/remote digest comparison; state exactly which mathematical condition failed.
4. Accept user input and hexadecimal input without changing the reusable core function.
5. Measure key generation, forward operation, and reverse operation separately over repeated trials.
6. Process five different message sizes and present time, output size, and overhead in a table.
7. Modify one bit of the message/ciphertext/signature and record the resulting behavior.
8. Turn the algorithm into a TCP client/server program with explicit length framing.
9. Demonstrate its best-known classroom attack or misuse, then give two concrete mitigations.
10. Combine it with a second algorithm from the same lab; reverse operations in the correct order and explain why.

