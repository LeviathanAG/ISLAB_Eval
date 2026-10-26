# Lab 8 solution notes

`solutions.py` covers the ten-document SSE and Paillier-backed index exercises.
The manual's additional system-tool questions are covered by:

- `gnupg_tools.py`: safe GnuPG command construction and execution helpers;
  install the `gpg` executable and configure keys before running real
  encryption/signature operations.
- `snort_tools.py`: Snort 3 configuration/PCAP/live command builders plus
  existing alert-log analysis; Snort is not installed or invoked automatically.

Both wrappers use argument lists rather than shell strings.  Snort monitoring
must be limited to authorized interfaces and captures.

