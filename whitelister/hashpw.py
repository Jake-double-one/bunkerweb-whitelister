"""``python -m whitelister.hashpw``: print a PBKDF2 hash for WHITELISTER_PASSWORD_HASH."""

from __future__ import annotations

import getpass
import sys

from .security import hash_password


def main() -> int:
    if len(sys.argv) > 1:
        print("usage: python -m whitelister.hashpw  (the password is read from the terminal, never from arguments)", file=sys.stderr)
        return 2
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Repeat: ")
    if first != second:
        print("passwords do not match", file=sys.stderr)
        return 1
    if len(first) < 12:
        print("use at least 12 characters", file=sys.stderr)
        return 1
    print(hash_password(first))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
