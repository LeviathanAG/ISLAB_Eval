# Solved PYQs

These are the two menu-driven programs requested in the objective:

| File | Main techniques |
|---|---|
| `secure_grant_expense_portal.py` | AES-192-CBC, Paillier addition, MD5 record hash, RSA-PSS, persistent role menus |
| `national_e_voting_system.py` | SHA-512, AES-256-CBC, RSA-OAEP with a 4096-bit default key, ElGamal signatures, Paillier one-hot tallying, trusted timestamps, searchable indexes, 2-of-2 threshold demo |

Both programs use fixed local data folders, keep JSON/PEM state across
restarts, and report malformed or tampered records without crashing the menus.

The first visit to each menu role creates a salted PBKDF2 password record;
later visits require that role's password.  Runtime keys and records under the
default `solved_pyqs/data/` directory are ignored by Git.

Start either program and use its menu:

```bash
python3 solved_pyqs/secure_grant_expense_portal.py
python3 solved_pyqs/national_e_voting_system.py
```

The default RSA-4096 and Paillier-1024 generation in the e-voting program is
intentionally heavier than the smaller explicit test configurations.

