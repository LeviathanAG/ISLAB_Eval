# Import-to-documentation map

Pages in this directory were downloaded from the official documentation sites
on 2026-10-25.

## Python standard library

| Imported module/API | Local page |
|---|---|
| `argparse` | `python_argparse.html` |
| `base64` | `python_base64.html` |
| `collections.abc` | `python_collections_abc.html` |
| `collections.Counter` | `python_collections.html` |
| `datetime` | `python_datetime.html` |
| `decimal` | `python_decimal.html` |
| `getpass` | `python_getpass.html` |
| `hashlib` | `python_hashlib.html` |
| `hmac` | `python_hmac.html` |
| `json` | `python_json.html` |
| `math` | `python_math.html` |
| `os` | `python_os.html` |
| `pathlib` | `python_pathlib.html` |
| `random` | `python_random.html` |
| `re` | `python_re.html` |
| `secrets` | `python_secrets.html` |
| `socket` | `python_socket.html` |
| `string` | `python_string.html` |
| `shutil` | `python_shutil.html` |
| `sys` | `python_sys.html` |
| `subprocess` | `python_subprocess.html` |
| `tempfile` | `python_tempfile.html` |
| `time` | `python_time.html` |
| `typing` | `python_typing.html` |
| `unittest` | `python_unittest.html` |

## `cryptography`

| Imported API | Local page |
|---|---|
| `cryptography.exceptions` | `cryptography_exceptions.html` |
| `cryptography.hazmat.primitives` | `cryptography_primitives.html` |
| AES/CBC and symmetric padding | `cryptography_symmetric_encryption.html` |
| RSA | `cryptography_rsa.html` |
| asymmetric padding | `cryptography_asymmetric_padding.html` |
| serialization | `cryptography_serialization.html` |

The lab code also imports the repository's existing `digital_signatures.py`;
that module's public functions are described in the generated
`crypto_helpers.md` notes and in its source docstrings.

## Preserved upstream endsems references

The cloned upstream reference scripts additionally mention PyCryptodome and
the `phe` Paillier package.  Their official API pages are downloaded locally
as `pycryptodome_*.html` and `phe_paillier.html`; the dependency-light solved
programs in this checkout do not import those packages.

