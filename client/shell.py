#!/usr/bin/env python3
import sys
import time
import os
import asyncio
import tty

from pwn import *

if len(sys.argv) != 3:
    print("Usage: " + sys.argv[0] + " <hostname> <port>")
    sys.exit(1)

print("Connecting to " + sys.argv[1] + ":" + sys.argv[2])
r = remote(sys.argv[1], int(sys.argv[2]))

r.sendline(b"tty")

r.recvuntil(b"4 TTY")

tty.setraw(0)
print("\x1b[?25h") #enable cursor

no = r.fileno()

def sock_reader():
    data = os.read(no, 1024)
    if b"END_OF_COMMUNICATION\n" in data:
        print("\r")
        tty.setcbreak(0)
        sys.exit(0)
    os.write(1, data)

def stdin_reader():
    data = os.read(0, 1024)
    os.write(no, data)

loop = asyncio.get_event_loop()
loop.add_reader(no, sock_reader)
loop.add_reader(0, stdin_reader)

loop.run_forever()
