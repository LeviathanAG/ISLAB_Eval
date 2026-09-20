"""Minimal menu skeleton - replace only encrypt_data/decrypt_data.

Use this when the question says "write a menu-driven program".  Keeping input,
menu control, and algorithm logic separate makes the answer easy to modify.
"""


def encrypt_data(plaintext: str, key: str) -> str:
    """TODO: replace this body with the required cipher's encrypt function."""
    return f"encrypted({plaintext}) with key={key}"


def decrypt_data(ciphertext: str, key: str) -> str:
    """TODO: replace this body with the required cipher's decrypt function."""
    return f"decrypted({ciphertext}) with key={key}"


def main():
    while True:
        print("\n1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            plaintext = input("Enter plaintext: ")
            key = input("Enter key: ").strip()
            print("Ciphertext:", encrypt_data(plaintext, key))

        elif choice == "2":
            ciphertext = input("Enter ciphertext: ").strip()
            key = input("Enter key: ").strip()
            print("Plaintext:", decrypt_data(ciphertext, key))

        elif choice == "3":
            print("Exiting")
            break

        else:
            print("Invalid choice; enter 1, 2, or 3")


if __name__ == "__main__":
    main()

