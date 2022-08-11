#!/usr/bin/env python3
import sys
import time
import os
import asyncio
import tty

os.environ["PWNLIB_SILENT"]='1'
os.environ["PWNLIB_NOTERM"]='1'

from pwn import *

if len(sys.argv) != 4:
    print("Usage: " + sys.argv[0] + " <hostname> <port> <bind port>")
    sys.exit(1)

#context.log_level = 'critical'

r = remote(sys.argv[1], int(sys.argv[2]))

r.sendline(b"bind " + sys.argv[3].encode("utf-8"))

r.recvuntil(b"1 ")
r.recvuntil(b"\n")

if r.recvuntil(b"4 ACCEPT\n", timeout=1) == b'':
    os.write(1, r.clean())
    sys.exit(0)

no = r.fileno()

def sock_reader():
    data = os.read(no, 1024)
    if b"END_OF_COMMUNICATION\n" in data:
        sys.exit(0)
    os.write(1, data)

def stdin_reader():
    data = os.read(0, 1024)
    os.write(no, data)

loop = asyncio.get_event_loop()
loop.add_reader(no, sock_reader)
loop.add_reader(0, stdin_reader)

loop.run_forever()
