#!/usr/bin/env python3
import sys
import time
import os
from pwn import *


if len(sys.argv) <= 4:
    print("Usage: " + sys.argv[0] + " <hostname> <port> <remotefile> <localfile>")
    sys.exit(1)

print("Connecting to " + sys.argv[1] + ":" + sys.argv[2])
r = remote(sys.argv[1], int(sys.argv[2]))


r.sendline(b"download " + sys.argv[3].encode("utf-8"))

r.recvuntil(b"1 ")
r.recvuntil(b"\n")

if r.recvuntil(b"4 BINSND", timeout=1) == b'':
    sys.stdout.write(r.clean())
    sys.exit(0)
r.recvuntil(b"SIZE ")

b = r.recvuntil(b"\n", drop=True)
size = int(b, 16)
data = r.recvn(size)

open(sys.argv[4], "wb").write(data)

sys.stdout.write(r.clean(1))
