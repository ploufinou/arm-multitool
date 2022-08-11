#!/usr/bin/env python3
import sys
import time
import os
from pwn import *


if len(sys.argv) <= 4:
    print("Usage: " + sys.argv[0] + " <hostname> <port> <localfile> <remotefile>")
    sys.exit(1)

print("Connecting to " + sys.argv[1] + ":" + sys.argv[2])
r = remote(sys.argv[1], int(sys.argv[2]))

data = open(sys.argv[3], "rb").read()

r.sendline(b"upload " + sys.argv[4].encode("utf-8") + b" " + str(len(data)).encode("utf-8"))

r.recvuntil(b"1 ")
r.recvuntil(b"\n")

if r.recvuntil(b"4 BINRCV\n", timeout=1) == b'':
    sys.stdout.write(r.clean())
    sys.exit(0)

r.send(data)
sys.stdout.write(r.clean(1))
