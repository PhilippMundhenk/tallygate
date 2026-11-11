#!/usr/bin/env python3
"""Create CONTROL_PASSWORD_HASH:  python3 control/hashpw.py   (prompts for the password)"""

import getpass
import hashlib
import os

pw = getpass.getpass("Password: ")
if pw != getpass.getpass("Repeat: "):
    raise SystemExit("mismatch")
salt = os.urandom(16)
print("scrypt:" + salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex())
