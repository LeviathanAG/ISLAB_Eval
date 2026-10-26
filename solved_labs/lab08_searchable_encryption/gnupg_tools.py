"""Safe GnuPG command wrapper for Lab 8's additional exercise.

GnuPG is a system executable, not a Python package.  These helpers never use
``shell=True``: every user-provided path or identity remains one argument.
They report a missing executable or failed command instead of claiming that a
cryptographic operation succeeded.

Usage examples:
    python3 solved_labs/lab08_searchable_encryption/gnupg_tools.py
    encrypt_command("alice@example.test", "message.txt", "message.gpg")
    sign_command("alice@example.test", "message.txt", "message.sig")
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def gpg_executable() -> str | None:
    """Return the installed GnuPG path, or ``None`` when it is unavailable."""

    return shutil.which("gpg")


def encrypt_command(recipient: str, source: str | Path, output: str | Path) -> list[str]:
    """Build a public-key encryption command for one recipient."""

    return ["gpg", "--output", str(output), "--encrypt", "--recipient", recipient, str(source)]


def decrypt_command(source: str | Path, output: str | Path) -> list[str]:
    """Build a decryption command that writes plaintext to ``output``."""

    return ["gpg", "--output", str(output), "--decrypt", str(source)]


def sign_command(signer: str, source: str | Path, output: str | Path) -> list[str]:
    """Build an armored detached-signature command."""

    return [
        "gpg",
        "--local-user",
        signer,
        "--armor",
        "--output",
        str(output),
        "--detach-sign",
        str(source),
    ]


def verify_command(signature: str | Path, source: str | Path) -> list[str]:
    """Build a detached-signature verification command."""

    return ["gpg", "--verify", str(signature), str(source)]


def run_gpg(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a previously built command and preserve useful text diagnostics."""

    if gpg_executable() is None:
        raise FileNotFoundError("GnuPG executable was not found; install gnupg first")
    return subprocess.run(command, check=True, capture_output=True, text=True)


def demo() -> None:
    """Print availability and safe command examples without changing files."""

    executable = gpg_executable()
    print("GnuPG available:", executable is not None)
    print("Encryption command:", encrypt_command("recipient@example.test", "plain.txt", "plain.gpg"))
    print("Detached-signature command:", sign_command("alice@example.test", "plain.txt", "plain.sig"))
    if executable is None:
        print("Install gnupg before executing these commands.")


def run_menu() -> None:
    """Show GnuPG helpers and optionally run a selected safe operation."""

    while True:
        print("\n=== GnuPG menu ===")
        print("1. Show command templates")
        print("2. Run an encryption/decryption/signature command")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice == "1":
            demo()
        elif choice == "2":
            print("1. Encrypt  2. Decrypt  3. Sign  4. Verify")
            operation = input("Choose operation: ").strip()
            try:
                if operation == "1":
                    command = encrypt_command(
                        input("Recipient identity: ").strip(),
                        input("Plaintext path: ").strip(),
                        input("Output path: ").strip(),
                    )
                elif operation == "2":
                    command = decrypt_command(
                        input("Encrypted path: ").strip(), input("Output path: ").strip()
                    )
                elif operation == "3":
                    command = sign_command(
                        input("Signer identity: ").strip(),
                        input("Plaintext path: ").strip(),
                        input("Signature path: ").strip(),
                    )
                elif operation == "4":
                    command = verify_command(
                        input("Signature path: ").strip(), input("Plaintext path: ").strip()
                    )
                else:
                    print("Invalid operation.")
                    continue
                result = run_gpg(command)
                print(result.stdout or result.stderr or "GnuPG command completed.")
            except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
                print(f"GnuPG operation failed: {exc}")
        else:
            print("Invalid choice.")


if __name__ == "__main__":  # pragma: no cover - system-dependent command runner.
    run_menu()

