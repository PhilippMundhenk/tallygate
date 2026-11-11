#!/usr/bin/env python3
"""Create CONTROL_PASSWORD_HASH:  python3 control/hashpw.py   (prompts for the password)

Format: scrypt:<log2 N>:<salt hex>:<hash hex>  (N = 2^16, r = 8, p = 1; ~64 MiB per check)."""

import getpass
import hashlib
import os

LOG2N = 16
pw = getpass.getpass("Password: ")
if len(pw) < 12:
    raise SystemExit("use at least 12 characters")
if pw != getpass.getpass("Repeat: "):
    raise SystemExit("mismatch")
salt = os.urandom(16)
n = 2**LOG2N
digest = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, maxmem=256 * n * 8 + 1024 * 1024)
print(f"scrypt:{LOG2N}:{salt.hex()}:{digest.hex()}")
